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

try {
    // Fetch available audio tracks. Fields are encrypted/escaped during execution output.
    $query = "SELECT id, track_name, file_path, duration FROM audio_tracks ORDER BY track_name ASC";
    $stmt = $conn->prepare($query);
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

if (isset($_GET['play_id'])) {
    $target_id = (int)$GET['play_id'];
    
    // Parameterized lookup to secure track path definition
    $track_stmt = $conn->prepare("SELECT track_name, file_path FROM audio_tracks WHERE id = ?");
    $track_stmt->bind_param("i", $target_id);
    $track_stmt->execute();
    $track_res = $track_stmt->get_result()->fetch_assoc();
    $track_stmt->close();
    
    if ($track_res) {
        // The database must store only the file name (e.g., "song1.mp3"). We hardcode the folder directory path prefix on the server. This neutralizes Path Traversal (../../etc/passwd)
        $safe_filename = basename($track_res['file_path']); 
        $active_track_path = "uploads/audio/" . $safe_filename;
        $active_track_name = $track_res['track_name'];
    }
}
?>

<style>
    .audio-split-container {
        display: flex;
        gap: 20px;
        margin-top: 15px;
    }
    .audio-list-panel {
        flex: 1;
        max-height: 300px;
        overflow-y: auto; /* Scrollbar requirement */
        border: 1px solid #def2f1;
        border-radius: 6px;
        padding: 10px;
        background: #fdfdfd;
    }
    .audio-player-panel {
        flex: 1;
        background-color: #feffff;
        border: 2px dashed #3aafa9;
        border-radius: 6px;
        padding: 20px;
        display: flex;
        flex-direction: column;
        justify-content: center;
        align-items: center;
    }
    .track-item {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 10px;
        border-bottom: 1px solid #f0f0f0;
        transition: background 0.2s;
    }
    .track-item:hover { background-color: #f4f6f9; }
    .track-item.playing { background-color: #def2f1; font-weight: bold; }
    .audio-element { width: 100%; margin-top: 15px; }
</style>

<h3>Audio Streaming Vault</h3>
<p>Select a track from the scrollable console panel to launch the streaming subsystem container.</p>

<div class="audio-split-container">
    <div class="audio-list-panel">
        <?php if ($result->num_rows === 0): ?>
            <p style="text-align: center; margin-top: 100px; color: #7f8c8d;">No audio tracks found.</p>
        <?php else: ?>
            <?php while ($track = $result->fetch_assoc()): ?>
                <?php 
                    $is_playing = isset($target_id) && ($target_id === (int)$track['id']);
                ?>
                <div class="track-item <?php echo $is_playing ? 'playing' : ''; ?>">
                    <div>
                        <span><?php echo htmlspecialchars($track['track_name'], ENT_QUOTES, 'UTF-8'); ?></span>
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

<?php
$stmt->close();
?>
