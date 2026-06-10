<?php
/**
 * SUBMODULE: Search Results Panel (search in title or author)
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
        } else {
            // A non-premium user cannot find premium audio tracks in search
            $query = "SELECT id, title, author AS extra_info, is_premium, 'audio' AS type FROM media WHERE type = 'audio' AND (title LIKE ? OR author LIKE ?) AND is_premium = 0 ORDER BY title ASC LIMIT 20";
        }
    } else {
        // Search inside lyrics repository (Default)
        if ($is_premium_user) {
            // A premium user can find all lyrics in search
            $query = "SELECT id, title, author AS extra_info, is_premium, 'lyrics' AS type FROM media WHERE type = 'lyrics' AND (title LIKE ? OR author LIKE ?) ORDER BY title ASC LIMIT 20";
        } else {
            // A non-premium user cannot find premium lrics in search
            $query = "SELECT id, title, author AS extra_info, is_premium, 'lyrics' AS type FROM media WHERE type = 'lyrics' AND (title LIKE ? OR author LIKE ?) AND is_premium = 0 ORDER BY title ASC LIMIT 20";
        }
    }

    $stmt = $conn->prepare($query);
    $stmt->bind_param("ss", $like_param, $like_param);
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

<div style="margin-bottom: 20px;">
    <h3 style="margin: 0 0 5px 0; color: #17252a; font-size: 20px; font-weight: bold;">Search Results</h3>
    <span style="color: #64748b; font-size: 14px; display: block; line-height: 1.4;">
        Showing matches for keyword <strong style="color: #17252a;">"<?php echo htmlspecialchars($search_query, ENT_QUOTES, 'UTF-8'); ?>"</strong> 
        inside the <strong style="color: #2b7a78; text-transform: uppercase;"><?php echo htmlspecialchars($search_context, ENT_QUOTES, 'UTF-8'); ?></strong> repository.<br>
        <small style="color: #94a3b8;">* The system actively scans both <strong>titles</strong> and <strong>authors/artists</strong> matching your parameters.</small>
    </span>
</div>

<?php if (empty($results)): ?>
    <div style="text-align: center; padding: 50px; color: #64748b; background: #f8fafc; border: 1px dashed #cbd5e1; border-radius: 6px; font-style: italic;">
        No matches found. Try modifying your keywords or switching repository sections.
    </div>
<?php else: ?>
    <div style="border: 1px solid #cbd5e1; border-radius: 6px; overflow: hidden; background: white;">
        <ul class="search-results-list" style="list-style: none; padding: 0; margin: 0;">
            <?php 
            $cnt = 0;
            foreach ($results as $item): 
                $cnt++;
                $bg_color = ($cnt % 2 === 0) ? '#f8fafc' : '#ffffff';
                $border_bottom = ($cnt === count($results)) ? 'none' : '1px solid #e2e8f0';
            ?>
                <li class="search-result-item" style="display: flex; justify-content: space-between; align-items: center; padding: 14px 20px; background-color: <?php echo $bg_color; ?>; border-bottom: <?php echo $border_bottom; ?>; transition: background 0.15s;">
                    <div style="max-width: 75%; overflow: hidden;">
                        <span class="result-title" style="color: #0f172a; font-weight: 500; font-size: 15px; display: block; text-overflow: ellipsis; white-space: nowrap;">
                            <?php echo htmlspecialchars($item['title'], ENT_QUOTES, 'UTF-8'); ?>
                            <?php echo $item['is_premium'] ? ' <span class="badge-file-premium" style="margin-left: 5px;">PREMIUM</span>' : ''; ?>
                        </span>
                        <span class="result-sub" style="color: #64748b; font-size: 12px; margin-top: 3px; display: inline-block;">
                            <strong>Artist/Author:</strong> <?php echo htmlspecialchars($item['extra_info'], ENT_QUOTES, 'UTF-8'); ?>
                        </span>
                    </div>
                    <div>
                        <?php if ($item['type'] === 'audio'): ?>
                            <a href="dashboard.php?view=audio&play_id=<?php echo (int)$item['id']; ?>" class="page-link" style="font-size: 12px; padding: 5px 12px; border-radius: 4px; display: inline-block; text-decoration: none;">Stream Track</a>
                        <?php else: ?>
                            <a href="dashboard.php?view=lyrics&action=view&id=<?php echo (int)$item['id']; ?>" class="page-link" style="font-size: 12px; padding: 5px 12px; border-radius: 4px; display: inline-block; text-decoration: none;">Read Lyrics</a>
                        <?php endif; ?>
                    </div>
                </li>
            <?php endforeach; ?>
        </ul>
    </div>
    
    <div style="margin-top: 20px; text-align: left;">
        <a href="dashboard.php?view=<?php echo htmlspecialchars($search_context, ENT_QUOTES, 'UTF-8'); ?>" class="page-link" style="padding: 6px 14px; font-size: 13px; background-color: #64748b;">
            &laquo; Back to Full <?php echo ucfirst($search_context); ?> List
        </a>
    </div>
<?php endif; ?>
