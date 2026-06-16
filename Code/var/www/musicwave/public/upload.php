<?php
/**
 * UPLOAD / INGESTION CONTROLLER
 * Handles secure lyrics insertion and audio file uploads with strict binary validation.
 */

require_once __DIR__ . '/../config/db_config.php';
require_once DIR_INCLUDES . 'db_connect.php';
require_once DIR_INCLUDES . 'logger_setup.php';
require_once DIR_INCLUDES . 'security_utils.php';

SecurityUtils::startSecureSession();		// start secure session

// Access control: If the user is not authenticated, we log the event and redirect to the login page.
if (!isset($_SESSION['user_id'])) {
    global $securityLogger;
    
    $client_ip = $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN_IP';		// take user ip for the log
    $requested_uri = $_SERVER['REQUEST_URI'] ?? 'upload.php';		// take the requested uri for the log
    
    $securityLogger->warning("Unauthorized dashboard access attempt intercepted", ["client_ip" => $client_ip,"requested_url" => $requested_uri]);
    
    header("Location: login.php?error=unauthorized");			// redirect
    exit();
}

SecurityUtils::sendSecurityHeaders();		// security headers

// Generate a strong, secure random token if it doesn't exist
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$message = "";
$error = false;
$user_id = $_SESSION['user_id'];

// Handle Form Submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // control check in case of huge audio filee
    if (empty($_POST) && isset($_SERVER['CONTENT_LENGTH']) && $_SERVER['CONTENT_LENGTH'] > 0) {
        global $errorLogger;
        $errorLogger->warning("POST request discarded by server due to size limits", ["user_id" => $_SESSION['user_id'] ?? 'ANONYMOUS',"content_length" => $_SERVER['CONTENT_LENGTH']]);	// write lo log
        $message = "The uploaded file exceeds the maximum server transmission capacity. Maximum allowed size is 10MB. Please try a smaller file.";
        $error = true;
    }
    else{

    // check presence and validity of the token. Use of hash_equals to prevent timing attack during string comparision (apply Costant-Time Comparison)
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        global $securityLogger;
    	$securityLogger->warning("CSRF attack attempt blocked on upload action", ["ip" => $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN_IP']);	// write in security log
    	header("HTTP/1.1 403 Forbidden");			// redirect ot an error page to visualize the attack for the user
    	exit("Security Error: Invalid or missing CSRF Token.");
    }
    // regenerate a new anti-CSRF token for the form in case the page is reloaded with errors.
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    
    // sanitize all the inputs
    $upload_type = SecurityUtils::sanitizeInput($_POST['upload_type'] ?? '');
    $title = SecurityUtils::sanitizeInput($_POST['title'] ?? '');
    $author = SecurityUtils::sanitizeInput($_POST['author'] ?? '');
    $is_premium = isset($_POST['is_premium']) ? 1 : 0;
    
    // check and validate the required fields (title and author)
    if (empty($title) || empty($author)) {
        $message = "Title and Author fields are strictly required.";	// missing fields
        $error = true;
    } elseif (strlen($title) > MAX_TITLE_AUTHOR_LENGTH || strlen($author) > MAX_TITLE_AUTHOR_LENGTH) {
        $message = "Title and Author must not exceed 255 characters.";	// incorrect fields
        $error = true;
    } else {
    	// Apply strict whitelisting on lyrics and audio titles and authors
        $validated_title = SecurityUtils::validateMeta($title);
    	$validated_author = SecurityUtils::validateMeta($author);
        
        // titol, author control check anti-injestion
        if ($validated_title === false || $validated_author === false) {
            $message = "Invalid characters detected in Title or Author. Only letters, numbers, spaces, hyphens, and apostrophes are allowed.";
            $error = true;
        } else { 	
        // -- start: else control metadati -
        
        // -- CASE: LYRICS INGESTION -- 
        if ($upload_type === 'lyrics') {
            $lyrics_content = $_POST['content'] ?? '';	// get contenct (the lyrics text)
            
            // Enforce Max Capacity Protection (65,535 chars for standard MySQL TEXT)
            if (empty(trim($lyrics_content))) {				// remove blanck space and check the len
                $message = "Lyrics content cannot be empty.";
                $error = true;
            } elseif (strlen($lyrics_content) > MAX_LYRICS_LENGTH) {	// control check fr maximum len
                $message = "Lyrics content is too large (Maximum 65,535 characters).";
                $error = true;
            } else {
                $sanitized_lyrics = SecurityUtils::validateLyrics($lyrics_content);	// Apply security validation filters for lyrics structural anomalies
                
                if ($sanitized_lyrics === false) {
		    $message = "Invalid characters detected in lyrics. Only standard text and basic punctuation are allowed.";	// write in security log in the validateLyrics function
		    $error = true;
		} else {
		    $stmt = $conn->prepare("INSERT INTO media (user_id, title, author, type, content, is_premium) VALUES (?, ?, ?, 'lyrics', ?, ?)");	// insert query
		    $stmt->bind_param("isssi", $user_id, $title, $author, $sanitized_lyrics, $is_premium);
		    
		    // check for execution completion
                    if ($stmt->execute()) {
                        $media_id = $conn->insert_id;
                        $accessLogger->info("New lyrics uploaded successfully", ["user_id" => $user_id, "media_id" => $media_id]);	// access log, operation success
                        $message = "Lyrics added successfully!";
                        $stmt->close();
                        
                        // On success, invalidate the token completely for the next request
                        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                    
                        header("Location: upload.php?status=success");
                        exit();
                    } else {
                        // 1062 error specific management (duplicate entry)
		        if ($conn->errno === 1062) {
			    $message = "This exact song title and author combination already exists in our repository.";
			    $error = true;
		        } else {
                            $errorLogger->error("Failed to insert lyrics into DB", ["error" => $conn->error, "user_id" => $user_id]);	// error log, operation failure
                            $message = "A database error occurred while saving the lyrics.";
                            $error = true;
                        }
                    }
		}  
            }
        }
        // -- CASE: AUDIO UPLOAD --
        elseif ($upload_type === 'audio') {
            // check if audio file is in request and check if the upload has done correct or not
            if (!isset($_FILES['audio_file']) || $_FILES['audio_file']['error'] !== UPLOAD_ERR_OK) {
                $message = "Please select a valid audio file. Ensure it does not exceed server limits.";	// error
                $error = true;
            } else {			// file uploaded correctly
            	// check all fields. When a user uploads a file via an HTML form, PHP receives this file and inserts all its information into the superglobal array.
                $file_tmp = $_FILES['audio_file']['tmp_name'];		// take the temp path file
                $file_size = $_FILES['audio_file']['size'];		// take the size
                $orig_filename = $_FILES['audio_file']['name'];		// take the original name of the file (when was in user's pc)
                
                // check strict Size Constraint (10 Megabytes maximum)
                if ($file_size > MAX_AUDIO_FILE_SIZE) {
                    $message = "The audio file is too large. Maximum allowed size is 10MB.";
                    
                    $error = true;
                } else {
                    // audio type Verification via Magic Bytes (MIME-type check)
                    $finfo = finfo_open(FILEINFO_MIME_TYPE);
                    $mime_type = finfo_file($finfo, $file_tmp);
                    finfo_close($finfo);
                    
                    // set of allowed audio formats (extensions)
                    $allowed_mimes = ['audio/mpeg'  => 'mp3'];
                        /* Future expansion examples:
			    'audio/ogg'   => 'ogg',
			    'audio/wav'   => 'wav',
			    'audio/x-wav' => 'wav'
			    */
                    
                    // check if the format is in the allowed format
                    if (!array_key_exists($mime_type, $allowed_mimes)) {
                        $securityLogger->warning("Suspicious file upload blocked: Invalid MIME-type detected", ["user_id" => $user_id, "original_name" => $orig_filename, "detected_mime" => $mime_type]);	// security log, wrong format
                        $message = "Invalid file format. Only standard MP3 files are allowed.";
                        $error = true;
                    } else {
                        $verified_ext = $allowed_mimes[$mime_type];		// get the correct extension mapped from verified MIME-type
                        
                        // cryptographic Renaming Strategy to neutralize execution vectors (replace user name for the audio file)
                        $crypto_token = bin2hex(random_bytes(16));				// first random string
                        $safe_filename = $crypto_token . "_" . time() . "." . $verified_ext;	// concanete the rndom string with time and format
                        $destination_path = DIR_UPLOADS_AUDIO . $safe_filename;			// create the path to save audio in the server
                        
                        $db_content_path = $safe_filename;					// save relative web path in the database content field

                        // secure move file out of temporary storage into the upload folder
                        if (move_uploaded_file($file_tmp, $destination_path)) {
                            $stmt = $conn->prepare("INSERT INTO media (user_id, title, author, type, content, is_premium) VALUES (?, ?, ?, 'audio', ?, ?)");	// insert query
                            $stmt->bind_param("isssi", $user_id, $title, $author, $db_content_path, $is_premium);
                            
                            // check for execution completion
                            if ($stmt->execute()) {			
                                $media_id = $conn->insert_id;
                                $accessLogger->info("New audio file uploaded successfully", ["user_id" => $user_id, "media_id" => $media_id]);	// log for successful file upload
                                $message = "Audio track uploaded successfully!";
                                
                                $stmt->close();
                    
		                header("Location: upload.php?status=success");
		                exit();
                            } else {
                                // rollback local file storage if database transaction fails
                                if (file_exists($destination_path)) {
                                    unlink($destination_path);
                                }
                                // 1062 error specific management (duplicate entry)
				if ($conn->errno === 1062) {
				    $message = "This exact song title and author combination already exists in our repository.";
				    $error = true;
				} else {
                                    $errorLogger->error("Database insertion failed for audio file storage", ["error" => $conn->error]);	// error log
                                    $message = "A database error occurred while saving the asset.";
                                    $error = true;
                                }
                            }
                        } else {
                            $errorLogger->error("Critical filesystem operation failure: move_uploaded_file failed", ["user_id" => $user_id, "destination" => $destination_path]);	// file upload filed
                            $message = "Failed to store the uploaded file on the server.";
                            $error = true;
                        }
                    }
                }
            }
        } else {
            $message = "Invalid operational context.";
            $error = true;
        }
        }	// -- end: else control metadati -
    }
    }
}	// -- end: post case --

// If it has reached the end of execution and there was an error (including the post_max_size one)
if ($error) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$safe_username = htmlspecialchars($_SESSION['username'] ?? 'User', ENT_QUOTES, 'UTF-8');	// get current username to print in the layout (with XSS prevention)
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <title>MusicWave - Upload Media</title>
    <meta charset="UTF-8">
    <link rel="stylesheet" href="<?php echo WEB_CSS; ?>style.css">
</head>
<body>

    <header class="header-hud">
        <h1>MusicWave</h1>
        <div class="welcome-text">Logged in as: <?php echo $safe_username; ?></div>
        <a href="logout.php" class="btn btn-logout">LOGOUT</a>
    </header>

    <a href="dashboard.php" class="btn btn-back">&larr; Back to Dashboard</a>

    <div class="upload-container">
        <h2>Upload New Media Asset</h2>

        <?php if (!empty($message)): ?>
            <div class="alert <?php echo $error ? 'alert-danger' : 'alert-success'; ?>">
                <?php echo htmlspecialchars($message, ENT_QUOTES, 'UTF-8'); ?>
            </div>
        <?php endif; ?>

        <div class="section-toggle">
            <button type="button" class="toggle-btn active" data-target="lyrics_section">Lyrics Form</button>
    	    <button type="button" class="toggle-btn" data-target="audio_section">Audio Track Form</button>
        </div>

        <div id="lyrics_section" class="upload-panel active">
            <?php if (isset($_GET['status']) && $_GET['status'] === 'success'): ?>
                <div class="success-banner">
            	    <strong>Success!</strong> Content uploaded successfully. You can now make another upload.
        	</div>
    	    <?php endif; ?>
        
            <form method="POST" action="upload.php">
                <input type="hidden" name="upload_type" value="lyrics">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
                
                <div class="form-group">
                    <label for="lyrics_title">Song Title</label>
                    <input type="text" id="lyrics_title" name="title" class="form-control" maxlength="<?php echo MAX_TITLE_AUTHOR_LENGTH; ?>" required>
                </div>
                <div class="form-group">
                    <label for="lyrics_author">Author</label>
                    <input type="text" id="lyrics_author" name="author" class="form-control" maxlength="<?php echo MAX_TITLE_AUTHOR_LENGTH; ?>" required>
                </div>
                <div class="form-group">
                    <label for="lyrics_content">Lyrics Text Body</label>
                    <textarea id="lyrics_content" name="content" class="form-control" rows="12" placeholder="Paste or type text lyrics here..." maxlength="<?php echo MAX_LYRICS_LENGTH; ?>" required></textarea>
                    <small class="help-text">Maximum capacity restriction: 65,535 characters.</small>
                </div>
                <div class="form-group">
                    <label>
                        <input type="checkbox" name="is_premium" value="1"> Mark as Premium Content
                    </label>
                </div>
                <button type="submit" class="btn btn-submit-green">Save Lyrics</button>
            </form>
        </div>

        <div id="audio_section" class="upload-panel">
            <form method="POST" action="upload.php" enctype="multipart/form-data">
                <input type="hidden" name="upload_type" value="audio">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
                
                <div class="form-group">
                    <label for="audio_title">Track Title</label>
                    <input type="text" id="audio_title" name="title" class="form-control" maxlength="<?php echo MAX_TITLE_AUTHOR_LENGTH; ?>" required>
                </div>
                <div class="form-group">
                    <label for="audio_author">Author</label>
                    <input type="text" id="audio_author" name="author" class="form-control" maxlength="<?php echo MAX_TITLE_AUTHOR_LENGTH; ?>" required>
                </div>
                <div class="form-group">
                    <label for="audio_file">Select Audio File</label>
                    <input type="hidden" name="MAX_FILE_SIZE" value="10485760">
                    <input type="file" id="audio_file" name="audio_file" class="form-control" accept="audio/mpeg, audio/ogg, audio/wav" required>
                    <small class="help-text">Allowed formats: MP3. Max file size configuration limit: 10MB.</small>
                </div>
                <div class="form-group">
                    <label>
                        <input type="checkbox" name="is_premium" value="1"> Mark as Premium Content
                    </label>
                </div>
                <button type="submit" class="btn btn-submit-green">Upload Audio Track</button>
            </form>
        </div>
    </div>

    <script src="<?php echo WEB_JS; ?>upload.js"></script>
</body>
</html>
