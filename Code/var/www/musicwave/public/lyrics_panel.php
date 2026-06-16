<?php
/**
 * SUBMODULE: Lyrics Panel
 * Context: Loaded inside dashboard.php
 * Security: Strict entry check, parameterized pagination, strict XSS escaping on database outputs.
 */

// Prevent direct file access. If this file is called outside of dashboard.php, $_SESSION['user_id'] might exist, but we ensure it's part of the main application flow.
if (!isset($_SESSION['user_id']) || !defined('DIR_PUBLIC')) {
    header("HTTP/1.1 403 Forbidden");
    exit("Direct access denied.");
}

global $conn, $securityLogger;

// Verifica se la connessione esiste
if (!isset($conn) || $conn === null) {
    die("<p class='text-danger'>[DEBUG] Errore: \$conn è NULL nel modulo lyrics!</p>");
}

// Extract premium permissions from the session set in the parent controller
$user_role = $_SESSION['role'] ?? 'standard';
$is_premium_user = ($user_role === 'premium');

// get type of action to distinguish what should be displayed (list of lyrics or the text of a specific one)
$action = $_GET['action'] ?? '';			# get action
$lyric_id = isset($_GET['id']) ? (int)$_GET['id'] : 0;	# get lyrics_id

// ------------ view single lyrics (action = biew) ------------
if ($action === 'view' && $lyric_id > 0) {
    try {
        // We also extract the text content, checking the user's role.
        if ($is_premium_user) {
            $view_query = "SELECT title, author, content, is_premium, created_at FROM media WHERE id = ? AND type = 'lyrics'";
        } else {
            $view_query = "SELECT title, author, content, is_premium, created_at FROM media WHERE id = ? AND type = 'lyrics' AND is_premium = 0";
        }
        
        $view_stmt = $conn->prepare($view_query);
        $view_stmt->bind_param("i", $lyric_id);
        $view_stmt->execute();
        $lyric_data = $view_stmt->get_result()->fetch_assoc();
        $view_stmt->close();
        
        if (!$lyric_data) {
            echo "<p class='text-warning-debug'>Content not found or access denied.</p>";
            echo '<p><a href="dashboard.php?view=lyrics" class="page-link">&laquo; Back to List</a></p>';
            return;
        }
        // -- end this part of php and start html code --
        ?>
        
        <div class="repo-header">
                <a href="dashboard.php?view=lyrics" class="page-link">&larr; Back to Lyrics Repository</a>
            </div>
            <div class="lyric-view-container">
                <h2 class="lyric-view-title">
                    <?php echo htmlspecialchars($lyric_data['title'], ENT_QUOTES, 'UTF-8'); ?>
                    <?php if ($lyric_data['is_premium']): ?>
                        <span class="badge-file-premium">PREMIUM</span>
                    <?php else: ?>
                        <span class="badge-file-standard">STANDARD</span>
                    <?php endif; ?>
                </h2>
                <p class="lyric-view-author">Author: <?php echo htmlspecialchars($lyric_data['author'], ENT_QUOTES, 'UTF-8'); ?></p>
                <hr class="lyric-divider">
             <div class="lyric-content-box"><?php echo htmlspecialchars($lyric_data['content'], ENT_QUOTES, 'UTF-8'); ?></div>
        </div>

        <?php
        // -- restart this part of php and end html code --
    } catch (Throwable $e) {
        global $errorLogger;
        $errorLogger->error("Error rendering lyric single view", ["error" => $e->getMessage(), "user_id" => $_SESSION['user_id'] ?? 'ANONYMOUS', "ip" => $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN_IP']);
        echo "<p class='text-danger'>An error occurred while opening the lyric.</p>";
    }
    return; 	// stop execution here to not show the table below
}

// ------------ lyrics list view (default) ------------

// secure pagination, input saniization - force the 'page' parameter to be a strict positive integer to eliminate SQL injection or unexpected type anomalies.
$current_page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
if ($current_page < 1) {
    $current_page = 1;
}

$records_per_page = 5;					# number of lyrics to visualize in the page
$offset = ($current_page - 1) * $records_per_page;	# offset indicate the number of lyrics of the past page (if sum to current index get the total index)

try {
    // Discriminate query for role-based counting. If the user is not premium, we exclude premium records at the database level.
    if ($is_premium_user) {
        $count_query = "SELECT COUNT(*) FROM media WHERE type = 'lyrics'";
    } else {
        $count_query = "SELECT COUNT(*) FROM media WHERE type = 'lyrics' AND is_premium = 0";
    }

    // calculate total pages (prepared Statement to be absolutely safe, even if no variables are inside)
    $count_stmt = $conn->prepare($count_query);
    $count_stmt->execute();
    $total_records = $count_stmt->get_result()->fetch_row()[0];		# get total number of lyrics in the DB
    $count_stmt->close();
    
    $total_pages = ceil($total_records / $records_per_page) ?: 1;	# get number of pages
    if ($current_page > $total_pages) 
    { 
    	$current_page = $total_pages; 
    	$offset = ($current_page - 1) * $records_per_page; 
    }

    // Record selection with strict control over the is_premium flag
    if ($is_premium_user) {
        $query = "SELECT id, title, author, is_premium, created_at FROM media WHERE type = 'lyrics' ORDER BY title ASC LIMIT ? OFFSET ?";
    } else {
        $query = "SELECT id, title, author, is_premium, created_at FROM media WHERE type = 'lyrics' AND is_premium = 0 ORDER BY title ASC LIMIT ? OFFSET ?";
    }
    
    $stmt = $conn->prepare($query);
    $stmt->bind_param("ii", $records_per_page, $offset);
    $stmt->execute();
    $result = $stmt->get_result();
    
} catch (Throwable $e) {
    // Log internal error without leaking system details to the end user
    global $errorLogger;
    $errorLogger->error("Database error inside lyrics submodule", ["error" => $e->getMessage(), "user_id" => $_SESSION['user_id'] ?? 'ANONYMOUS', "ip" => $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN_IP']);	# write log	
    echo "<p class='text-danger'>An error occurred while loading contents. Please try again later.</p>";	# error mex
    return;
}
?>

<div class="repo-header">
    <h3 class="section-title">Lyrics Central Hub</h3>
    <p class="text-muted">Browse through the available track texts within your permissions map.</p>
</div>

<table class="lyrics-table">
    <thead>
        <tr>
            <th class="col-title">Track Title</th>
            <th class="col-author">Artist</th>
            <th class="col-type">Access Level</th>
            <th class="col-date">Uploaded at</th>
            <th class="col-actions">Read</th>
        </tr>
    </thead>
    <tbody>
        <?php if ($total_records === 0): ?>
            <tr>
                <td colspan="5" class="empty-table-msg">No lyrics modules cataloged under this workspace filter view.</td>
            </tr>
        <?php else: ?>
            <?php 
            $count = 0;
            while ($row = $result->fetch_assoc()): 
                $count++;
                $is_last = ($count === $result->num_rows);
                $row_class = $is_last ? 'last-row' : '';
            ?>
                <tr class="<?php echo $row_class; ?>">
                    <td><div class="lyrics-table-title"><?php echo htmlspecialchars($row['title'], ENT_QUOTES, 'UTF-8'); ?></div></td>
                    <td><div class="lyrics-table-author"><?php echo htmlspecialchars($row['author'], ENT_QUOTES, 'UTF-8'); ?></div></td>
                    <td>
                        <?php echo $row['is_premium'] ? '<span class="badge-file-premium">PREMIUM</span>' : '<span class="badge-file-standard">STANDARD</span>'; ?>
                    </td>
                    <td><span class="lyrics-table-date"><?php echo htmlspecialchars($row['created_at'], ENT_QUOTES, 'UTF-8'); ?></span></td>
                    <td class="text-center">
                        <a href="dashboard.php?view=lyrics&action=view&id=<?php echo (int)$row['id']; ?>" class="page-link">Read</a>
                    </td>
                </tr>
            <?php endwhile; ?>
        <?php endif; ?>
    </tbody>
</table>

<div class="pagination-container">
    <?php
    	// visualize the link for the lyrics pages only if there are more than 1 page  
    	if ($total_pages > 1): 
    ?>
        <?php for ($i = 1; $i <= $total_pages; $i++): ?>
            <a href="dashboard.php?view=lyrics&page=<?php echo $i; ?>" class="page-link <?php echo ($i === $current_page) ? 'active' : ''; ?>">
                <?php echo $i; ?>
            </a>
        <?php endfor; ?>
    <?php endif; ?>
</div>
<?php $stmt->close(); ?>
