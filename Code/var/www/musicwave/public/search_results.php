<?php
/**
 * SUBMODULE: Search Results Panel
 * Context: Loaded inside dashboard.php when a query is submitted
 * Security: Direct access restriction, strict Context Whitelisting, 
 * Parameterized SQL queries (Anti-SQLi), and strict Output Encoding (Anti-XSS).
 */

// Prevent direct file access. Check DIR_PUBLIC because it's defined in db_config.php. db_config.php is included only by the main application (dashboard.php).
if (!isset($_SESSION['user_id']) || !defined('DIR_PUBLIC')) {
    header("HTTP/1.1 403 Forbidden");
    exit("Direct access denied.");
}

global $conn, $securityLogger;

$search_query = $_GET['query'] ?? '';		// content and query extraction. We grab the search string (already sanitized as basic text by the dashboard controller)

// Extract premium permissions from the session set in the parent controller
$user_role = $_SESSION['role'] ?? 'standard';
$is_premium_user = ($user_role === 'premium');

// Determine the search context (defaults to 'lyrics' if missing or tampered with)
$search_context = $_GET['view'] ?? 'lyrics'; 
if (!in_array($search_context, ['lyrics', 'audio', 'search'])) {
    $search_context = 'lyrics';						# default option
}

// If the dashboard forced the 'search' view, we might need a backup context parameter to know what to search
if ($search_context === 'search') {
    $search_context = $_GET['context'] ?? 'lyrics';
}

// If the query is empty, we abort immediately without stressing the database
if (empty($search_query)) {
    echo "<p style='color: #7f8c8d; text-align: center;'>Please enter a valid keyword to start searching.</p>";
    return;
}

// secure parameterized DB execution
$results = [];

try {
    // Prepare the wildcard string safely for the SQL "LIKE" operator
    // This prevents SQL injection because the structure of the query is already compiled
    $like_param = "%" . $search_query . "%";

    if ($search_context === 'audio') {
        // Search inside audio tracks
        if ($is_premium_user) {
            // A premium user can find all audio tracks in search
            $query = "SELECT id, title, author AS extra_info, is_premium, 'audio' AS type FROM media WHERE type = 'audio' AND (title LIKE ? OR author LIKE ?) ORDER BY title ASC LIMIT 20";
            $stmt = $conn->prepare($query);
            $stmt->bind_param("ss", $like_param, $like_param);
        } else {
            // A non-premium user cannot find premium audio tracks in search
            $query = "SELECT id, title, author AS extra_info, is_premium, 'audio' AS type FROM media WHERE type = 'audio' AND (title LIKE ? OR author LIKE ?) AND is_premium = 0 ORDER BY title ASC LIMIT 20";
            $stmt = $conn->prepare($query);
            $stmt->bind_param("ss", $like_param, $like_param);
        }
    } else {
        // Search inside lyrics repository (Default)
        if ($is_premium_user) {
            // A premium user can find all lyrics in search
            $query = "SELECT id, title, author AS extra_info, is_premium, 'lyrics' AS type FROM media WHERE type = 'lyrics' AND (title LIKE ? OR author LIKE ?) ORDER BY title ASC LIMIT 20";
            $stmt = $conn->prepare($query);
            $stmt->bind_param("ss", $like_param, $like_param);
        } else {
            // A non-premium user cannot find premium lrics in search
            $query = "SELECT id, title, author AS extra_info, is_premium, 'lyrics' AS type FROM media WHERE type = 'lyrics' AND (title LIKE ? OR author LIKE ?) AND is_premium = 0 ORDER BY title ASC LIMIT 20";
            $stmt = $conn->prepare($query);
            $stmt->bind_param("ss", $like_param, $like_param);
        }
    }

    $stmt->execute();
    $res = $stmt->get_result();
    // get all the results
    while ($row = $res->fetch_assoc()) {
        $results[] = $row;
    }
    $stmt->close();

} catch (Exception $e) {
    // Log the error internally, show a generic message to the user
    $securityLogger->error("Database error inside search submodule", ["error" => $e->getMessage()]);
    echo "<p style='color: red;'>An internal database error occurred during the search.</p>";
    return;
}
?>

<div class="search-meta-info">
    Search results for: <strong>"<?php echo htmlspecialchars($search_query, ENT_QUOTES, 'UTF-8'); ?>"</strong> 
    inside <strong><?php echo htmlspecialchars(strtoupper($search_context), ENT_QUOTES, 'UTF-8'); ?></strong>
</div>

<?php if (empty($results)): ?>
    <div style="text-align: center; margin-top: 50px; color: #7f8c8d; font-style: italic;">
        No matches found. Try modifying your keywords or switching repository sections.
    </div>
<?php else: ?>
    <ul class="search-results-list">
        <?php foreach ($results as $item): ?>
            <li class="search-result-item">
                <div>
                    <span class="result-title">
                        <?php echo htmlspecialchars($item['title'], ENT_QUOTES, 'UTF-8'); ?>
                        <?php echo $item['is_premium'] ? ' <span class="badge-file-premium">PREMIUM</span>' : ''; ?>
                    </span>
                    <br>
                    <span class="result-sub">
                        <?php echo $item['type'] === 'audio' ? 'Duration: ' : 'Artist: '; ?>
                        <?php echo htmlspecialchars($item['extra_info'], ENT_QUOTES, 'UTF-8'); ?>
                    </span>
                </div>
                <div>
                    <?php if ($item['type'] === 'audio'): ?>
                        <a href="dashboard.php?view=audio&play_id=<?php echo (int)$item['id']; ?>" class="page-link" style="font-size: 12px;">Stream Track</a>
                    <?php else: ?>
                        <a href="dashboard.php?view=lyrics&action=view&id=<?php echo (int)$item['id']; ?>" class="page-link" style="font-size: 12px;">Read Lyrics</a>
                    <?php endif; ?>
                </div>
            </li>
        <?php endforeach; ?>
    </ul>
<?php endif; ?>
