<?php
/**
 * SUBMODULE: Audio Panel
 * Context: Loaded inside dashboard.php
 * Security: Strict context check, strict XSS prevention, path traversal containment on audio streaming.
 */

// Prevent direct file access. Check DIR_PUBLIC because it's defined in db_config.php. db_config.php is included only by the main application (dashboard.php).
if (!isset($_SESSION['user_id']) || !defined('DIR_PUBLIC')) {
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
    $target_id = (int)$_GET['play_id'];
    
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

<div style="margin-bottom: 20px;">
    <h3 style="margin: 0 0 5px 0; color: #17252a; font-size: 20px; font-weight: bold;">Audio Streaming Vault</h3>
    <span style="color: #64748b; font-size: 14px;">Select a track from the scrollable console panel to launch the streaming subsystem container.</span>
</div>

<div class="audio-split-container" style="display: flex; gap: 25px; margin-top: 15px;">
    
    <div class="audio-list-panel" style="flex: 1.2; max-height: 420px; overflow-y: auto; border: 1px solid #cbd5e1; border-radius: 6px; background: white; box-shadow: inset 0 2px 4px rgba(0,0,0,0.02);">
        <?php if ($result->num_rows === 0): ?>
            <div style="text-align: center; padding: 60px 0; color: #64748b;">No audio tracks found in the database.</div>
        <?php else: ?>
            <?php 
            $cnt = 0;
            while ($track = $result->fetch_assoc()): 
                $cnt++;
                $is_playing = ($target_id === (int)$track['id']);
                // Colore di sfondo dinamico per lo zebra striping ed evidenziazione traccia in esecuzione
                if ($is_playing) {
                    $item_bg = '#def2f1';
                } else {
                    $item_bg = ($cnt % 2 === 0) ? '#f8fafc' : '#ffffff';
                }
                $border_bottom = ($cnt === $result->num_rows) ? 'none' : '1px solid #e2e8f0';
            ?>
                <div class="track-item" style="display: flex; justify-content: space-between; align-items: center; padding: 14px 18px; background-color: <?php echo $item_bg; ?>; border-bottom: <?php echo $border_bottom; ?>; transition: background 0.15s;">
                    <div style="max-width: 75%; overflow: hidden;">
                        <span style="color: #0f172a; font-weight: 500; font-size: 15px; display: block; text-overflow: ellipsis; white-space: nowrap;">
                            <?php echo htmlspecialchars($track['title'], ENT_QUOTES, 'UTF-8'); ?>
                            <?php echo $track['is_premium'] ? ' <span class="badge-file-premium" style="margin-left: 5px;">PREMIUM</span>' : ''; ?>
                        </span>
                        <span style="color: #64748b; font-size: 12px; margin-top: 2px; display: inline-block;">Author: <?php echo htmlspecialchars($track['author'], ENT_QUOTES, 'UTF-8'); ?></span>
                    </div>
                    <div>
                        <a href="dashboard.php?view=audio&play_id=<?php echo (int)$track['id']; ?>" class="page-link" style="font-size: 12px; padding: 5px 12px; border-radius: 4px; display: inline-block; background-color: <?php echo $is_playing ? '#17252a' : '#2b7a78'; ?>;">
                            <?php echo $is_playing ? 'Playing' : 'Stream'; ?>
                        </a>
                    </div>
                </div>
            <?php endwhile; ?>
        <?php endif; ?>
    </div>

    <div class="audio-player-panel" style="flex: 0.8; background: #f8fafc; padding: 30px; border-radius: 6px; display: flex; flex-direction: column; justify-content: center; align-items: center; border: 1px solid #cbd5e1; min-height: 200px;">
        <?php if (!empty($active_track_path)): ?>
            <div style="text-align: center; width: 100%;">
                <div style="background: #3aafa9; color: white; display: inline-block; padding: 4px 10px; font-size: 11px; font-weight: bold; border-radius: 12px; margin-bottom: 12px; text-transform: uppercase; letter-spacing: 0.05em;">
                    Live Streaming
                </div>
                <h4 style="margin: 0 0 20px 0; color: #17252a; font-size: 16px; font-weight: 600; line-height: 1.4;">
                    Now Playing:<br>
                    <span style="color:#2b7a78; font-size: 18px; font-weight: bold; display: block; margin-top: 5px;"><?php echo htmlspecialchars($active_track_name, ENT_QUOTES, 'UTF-8'); ?></span>
                </h4>
                
                <audio controls autoplay class="audio-element" controlsList="nodownload" style="width: 100%; max-width: 280px; margin-top: 10px;">
                    <source src="<?php echo htmlspecialchars($active_track_path, ENT_QUOTES, 'UTF-8'); ?>" type="audio/mpeg">
                    Your browser does not support the audio element.
                </audio>
                
                <div style="margin-top: 20px;">
                    <a href="dashboard.php?view=audio" style="color: #64748b; font-size: 12px; text-decoration: none; font-weight: 500;">&times; Stop Stream / Reset Player</a>
                </div>
            </div>
        <?php else: ?>
            <div style="color: #64748b; text-align: center; font-size: 14px; line-height: 1.6;">
                <svg style="width: 48px; height: 48px; color: #cbd5e1; margin-bottom: 10px;" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19V6l12-3v13M9 19c0 1.105-1.343 2-3 2s-3-.895-3-2 1.343-2 3-2 3 .895 3 2zm12-3c0 1.105-1.343 2-3 2s-3-.895-3-2 1.343-2 3-2 3 .895 3 2zM9 10l12-3"></path>
                </svg>
                <br>
                <span style="font-weight: 500; color: #94a3b8;">[ Media Engine Idle ]</span><br>
                Select a record to initialize safe streaming.
            </div>
        <?php endif; ?>
    </div>
</div>

<?php $stmt->close(); ?>
