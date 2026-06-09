<?php
/**
 * SUBMODULE: Audio Panel
 * Context: Loaded inside dashboard.php
 * Security: Strict context check, strict XSS prevention, path traversal containment on audio streaming.
 */

// Prevent direct file access. 
if (!isset($_SESSION['user_id']) || !defined('DIR_MODULES')) {
    header("HTTP/1.1 403 Forbidden");
    exit("Direct access denied.");
}

global $conn, $securityLogger;

$user_role = $_SESSION['role'] ?? 'standard';
$is_premium_user = ($user_role === 'premium');

try {
    // Filter audio records based on user privilege
    if ($is_premium_user) {
        $query = "SELECT id, title, author, is_premium FROM media WHERE type = 'audio' ORDER BY title ASC";
        $stmt = $conn->prepare($query);
    } else {
        $query = "SELECT id, title, author, is_premium FROM media WHERE type = 'audio' AND is_premium = 0 ORDER BY title ASC";
        $stmt = $conn->prepare($query);
    }
    $stmt->execute();
    $result = $stmt->get_result();
} catch (Exception $e) {
    $securityLogger->error("Database error inside audio submodule", ["error" => $e->getMessage()]);
    echo "<p style='color: red;'>Unable to load audio tracks repository.</p>";
    return;
}

// secure selection: Identify the active track to stream safely
$active_track_path = '';
$active_track_name = '';

// Safe playback of active track
if (isset($_GET['play_id'])) {
    $target_id = (int)$GET['play_id'];
    
    // check the specific file including the role logic
    if ($is_premium_user) {
        $track_stmt = $conn->prepare("SELECT title, content, is_premium FROM media WHERE id = ? AND type = 'audio'");
        $track_stmt->bind_param("i", $target_id);
    } else {
        $track_stmt = $conn->prepare("SELECT title, content, is_premium FROM media WHERE id = ? AND type = 'audio' AND is_premium = 0");
        $track_stmt->bind_param("i", $target_id);
    }
    
    $track_stmt->execute();
    $track_res = $track_stmt->get_result()->fetch_assoc();
    $track_stmt->close();
    
    if ($track_res) {
        // The database must store only the file name (e.g., "song1.mp3"). We hardcode the folder directory path prefix on the server. This neutralizes Path Traversal (../../etc/passwd)
        $safe_filename = basename($track_res['content']); 
        $active_track_path = "uploads/audio/" . $safe_filename;
        $active_track_name = $track_res['title'];
    } else {
        // If a standard user tries to brute force the ID of a premium file via a parameterized URL, we intercept the IDOR attack.
        $securityLogger->warning("BOLA/IDOR attempt intercepted: User tried to access unauthorized premium audio", ["user_id" => $_SESSION['user_id'], "attempted_track_id" => $target_id]);
        echo "<p style='color: red; font-weight: bold;'>Security Error: Unauthorized media asset request.</p>";
    }
}
?>

<h3>Audio Streaming Vault</h3>
<p>Select a track from the scrollable console panel to launch the streaming subsystem container.</p>

<div class="audio-split-container">
    <div class="audio-list-panel">
        <?php if ($result->num_rows === 0): ?>
            <p style="text-align: center; margin-top: 100px; color: #7f8c8d;">No audio tracks found.</p>
        <?php else: ?>
            <?php while ($track = $result->fetch_assoc()): ?>
                <?php $is_playing = isset($target_id) && ($target_id === (int)$track['id']); ?>
                <div class="track-item <?php echo $is_playing ? 'playing' : ''; ?>">
                    <div>
                        <span>
                            <?php echo htmlspecialchars($track['track_name'], ENT_QUOTES, 'UTF-8'); ?>
                            <?php echo $track['is_premium'] ? ' <span class="badge-file-premium">PREMIUM</span>' : ''; ?>
                        </span>
                        <br><small style="color: #7f8c8d;">Duration: <?php echo htmlspecialchars($track['duration'], ENT_QUOTES, 'UTF-8'); ?></small>
                    </div>
                    <a href="dashboard.php?view=audio&play_id=<?php echo (int)$track['id']; ?>" class="page-link" style="font-size: 12px;">
                        <?php echo $is_playing ? 'Reload' : 'Stream'; ?>
                    </a>
                </div>
            <?php endwhile; ?>
        <?php endif; ?>
    </div>

    <div class="audio-player-panel">
        <?php if (!empty($active_track_path)): ?>
            <h4>Now Playing: <span style="color:#2b7a78;"><?php echo htmlspecialchars($active_track_name, ENT_QUOTES, 'UTF-8'); ?></span></h4>
            
            <audio controls autoplay class="audio-element" controlsList="nodownload">
                <source src="<?php echo htmlspecialchars($active_track_path, ENT_QUOTES, 'UTF-8'); ?>" type="audio/mpeg">
                Your browser does not support the audio element.
            </audio>
        <?php else: ?>
            <div style="color: #7f8c8d; text-align: center;">
                [ Media Idle ]<br>Select a record to initialize safe streaming.
            </div>
        <?php endif; ?>
    </div>
</div>

<?php $stmt->close(); ?>
