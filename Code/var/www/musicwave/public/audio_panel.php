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
    <h3 class="section-title">Audio Download Vault</h3>
    <span class="text-muted">Select a track from the repository below to securely download the asset to your device.</span>
</div>

<div class="audio-list-panel">
    <?php if ($result->num_rows === 0): ?>
        <div style="text-align: center; padding: 60px 0;" class="text-muted">No audio tracks found in the database.</div>
    <?php else: ?>
        <?php 
        $cnt = 0;
        while ($track = $result->fetch_assoc()): 
            $cnt++;
            $item_bg_class = ($cnt % 2 === 0) ? 'track-item-bg-alt' : 'track-item-bg-white';
            $border_class = ($cnt === $result->num_rows) ? '' : 'track-item-border';
        ?>
            <div class="track-item <?php echo $item_bg_class . ' ' . $border_class; ?>">
                <div style="max-width: 75%;">
                    <span class="track-title">
                        <?php echo htmlspecialchars($track['title'], ENT_QUOTES, 'UTF-8'); ?>
                        <?php echo $track['is_premium'] ? ' <span class="badge-file-premium">PREMIUM</span>' : ''; ?>
                    </span>
                    <span class="track-author">Author: <?php echo htmlspecialchars($track['author'], ENT_QUOTES, 'UTF-8'); ?></span>
                </div>
                <div>
                    <form method="POST" action="download.php" target="download_container" style="margin: 0;">
                        <input type="hidden" name="id" value="<?php echo (int)$track['id']; ?>">
                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
                        
                        <button type="submit" class="btn-download-mp3">
                            Download MP3
                        </button>
                    </form>
                </div>
            </div>
        <?php endwhile; ?>
    <?php endif; ?>
</div>

<!-- iframe for download that doesn't change page but stays in the background -->
<iframe name="download_container" class="hidden-iframe"></iframe>
<?php $stmt->close(); ?>
