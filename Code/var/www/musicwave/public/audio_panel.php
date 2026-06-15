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

// Generate an anti-CSRF token specifically for the download actions if not already initialized in session
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
?>

<div style="margin-bottom: 20px;">
    <h3 style="margin: 0 0 5px 0; color: #17252a; font-size: 20px; font-weight: bold;">Audio Download Vault</h3>
    <span style="color: #64748b; font-size: 14px;">Select a track from the repository below to securely download the asset to your device.</span>
</div>

<div class="audio-list-panel" style="width: 100%; max-height: 500px; overflow-y: auto; border: 1px solid #cbd5e1; border-radius: 6px; background: white; box-shadow: inset 0 2px 4px rgba(0,0,0,0.02);">
    <?php if ($result->num_rows === 0): ?>
        <div style="text-align: center; padding: 60px 0; color: #64748b;">No audio tracks found in the database.</div>
    <?php else: ?>
        <?php 
        $cnt = 0;
        while ($track = $result->fetch_assoc()): 
            $cnt++;
            $item_bg = ($cnt % 2 === 0) ? '#f8fafc' : '#ffffff';
            $border_bottom = ($cnt === $result->num_rows) ? 'none' : '1px solid #e2e8f0';
        ?>
            <div class="track-item" style="display: flex; justify-content: space-between; align-items: center; padding: 14px 20px; background-color: <?php echo $item_bg; ?>; border-bottom: <?php echo $border_bottom; ?>; transition: background 0.15s;">
                <div style="max-width: 75%; overflow: hidden;">
                    <span style="color: #0f172a; font-weight: 500; font-size: 15px; display: block; text-overflow: ellipsis; white-space: nowrap;">
                        <?php echo htmlspecialchars($track['title'], ENT_QUOTES, 'UTF-8'); ?>
                        <?php echo $track['is_premium'] ? ' <span class="badge-file-premium" style="margin-left: 5px; background: #f1c40f; color: #000; padding: 2px 5px; font-size: 10px; font-weight: bold; border-radius: 3px;">PREMIUM</span>' : ''; ?>
                    </span>
                    <span style="color: #64748b; font-size: 12px; margin-top: 3px; display: inline-block;">Author: <?php echo htmlspecialchars($track['author'], ENT_QUOTES, 'UTF-8'); ?></span>
                </div>
                <div>
                    <form method="POST" action="download.php" target="download_container" style="margin: 0;">
                        <input type="hidden" name="id" value="<?php echo (int)$track['id']; ?>">
                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
                        
                        <button type="submit" style="font-size: 13px; padding: 8px 16px; border-radius: 4px; border: none; font-weight: bold; color: white; background-color: #2b7a78; cursor: pointer; transition: background 0.2s; text-transform: uppercase; letter-spacing: 0.5px;" onmouseover="this.style.backgroundColor='#1a5251'" onmouseout="this.style.backgroundColor='#2b7a78'">
                            Download MP3
                        </button>
                    </form>
                </div>
            </div>
        <?php endwhile; ?>
    <?php endif; ?>
</div>

<!-- iframe for download that doesn't change page but stays in the background -->
<iframe name="download_container" style="display:none; width:0; height:0; border:none;"></iframe>
<?php $stmt->close(); ?>
