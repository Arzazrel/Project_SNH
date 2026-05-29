<?php
/**
 * SUBMODULE: Search Results Panel
 * Context: Loaded inside dashboard.php when a query is submitted
 * Security: Direct access restriction, strict Context Whitelisting, 
 * Parameterized SQL queries (Anti-SQLi), and strict Output Encoding (Anti-XSS).
 */

// Prevent direct file access. 
if (!isset($_SESSION['user_id']) || !defined('DIR_MODULES')) {
    header("HTTP/1.1 403 Forbidden");
    exit("Direct access denied.");
}

global $conn, $securityLogger;

$search_query = $_GET['query'] ?? '';		// content and query extraction. We grab the search string (already sanitized as basic text by the dashboard controller)

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

// 3. SECURE PARAMETERIZED DATABASE EXECUTION
$results = [];

try {
    // Prepare the wildcard string safely for the SQL "LIKE" operator
    // This prevents SQL injection because the structure of the query is already compiled
    $like_param = "%" . $search_query . "%";

    if ($search_context === 'audio') {
        // Search inside audio tracks
        $query = "SELECT id, track_name AS title, duration AS extra_info, 'audio' AS type 
                  FROM audio_tracks 
                  WHERE track_name LIKE ? 
                  ORDER BY track_name ASC LIMIT 20";
    } else {
        // Search inside lyrics repository (Default)
        $query = "SELECT id, title, artist AS extra_info, 'lyrics' AS type 
                  FROM lyrics 
                  WHERE title LIKE ? OR artist LIKE ? 
                  ORDER BY title ASC LIMIT 20";
    }

    $stmt = $conn->prepare($query);
    
    // Dynamically bind parameters based on the query structure
    if ($search_context === 'audio') {
        $stmt->bind_param("s", $like_param);
    } else {
        $stmt->bind_param("ss", $like_param, $like_param);
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

<style>
    .search-meta-info {
        margin-bottom: 20px;
        color: #555;
        font-size: 15px;
    }
    .search-results-list {
        list-style: none;
        padding: 0;
        margin: 0;
    }
    .search-result-item {
        padding: 15px;
        border: 1px solid #def2f1;
        border-radius: 6px;
        margin-bottom: 10px;
        background-color: #fdfdfd;
        display: flex;
        justify-content: space-between;
        align-items: center;
        transition: background 0.2s;
    }
    .search-result-item:hover {
        background-color: #f4f6f9;
        border-color: #3aafa9;
    }
    .result-title {
        font-weight: bold;
        color: #17252a;
    }
    .result-sub {
        font-size: 13px;
        color: #7f8c8d;
    }
</style>

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
                    <span class="result-title"><?php echo htmlspecialchars($item['title'], ENT_QUOTES, 'UTF-8'); ?></span>
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
