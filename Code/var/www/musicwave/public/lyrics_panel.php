<?php
/**
 * SUBMODULE: Lyrics Panel
 * Context: Loaded inside dashboard.php
 * Security: Strict entry check, parameterized pagination, strict XSS escaping on database outputs.
 */

// Prevent direct file access. If this file is called outside of dashboard.php, $_SESSION['user_id'] might exist, but we ensure it's part of the main application flow.
if (!isset($_SESSION['user_id']) || !defined('DIR_MODULES')) {
    header("HTTP/1.1 403 Forbidden");
    exit("Direct access denied.");
}

global $conn, $securityLogger;

// Extract premium permissions from the session set in the parent controller
$user_role = $_SESSION['role'] ?? 'standard';
$is_premium_user = ($user_role === 'premium');

// secure pagination, input saniization - force the 'page' parameter to be a strict positive integer to eliminate SQL injection or unexpected type anomalies.
$current_page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
if ($current_page < 1) {
    $current_page = 1;
}

$records_per_page = 5;					# number of lyrics to visualize in the page
$offset = ($current_page - 1) * $records_per_page;	# offset indicate the number of lyrics of the pas page (if sum to current index get the total index)

try {
    // Discriminate query for role-based counting. If the user is not premium, we exclude premium records at the database level.
    if ($is_premium_user) {
        $count_query = "SELECT COUNT(*) FROM media WHERE type = 'lyrics'";
        $count_stmt = $conn->prepare($count_query);
    } else {
        $count_query = "SELECT COUNT(*) FROM media WHERE type = 'lyrics' AND is_premium = 0";
        $count_stmt = $conn->prepare($count_query);
    }

    // calculate total pages (prepared Statement to be absolutely safe, even if no variables are inside)
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
        $query = "SELECT id, title, artist, is_premium, created_at FROM media WHERE type = 'lyrics' ORDER BY title ASC LIMIT ? OFFSET ?";
        $stmt = $conn->prepare($query);
        $stmt->bind_param("ii", $records_per_page, $offset);
    } else {
        $query = "SELECT id, title, artist, is_premium, created_at FROM media WHERE type = 'lyrics' AND is_premium = 0 ORDER BY title ASC LIMIT ? OFFSET ?";
        $stmt = $conn->prepare($query);
        $stmt->bind_param("ii", $records_per_page, $offset);
    }

    $stmt->execute();
    $result = $stmt->get_result();
    
} catch (Exception $e) {
    // Log internal error without leaking system details to the end user
    $securityLogger->error("Database error inside lyrics submodule", ["error" => $e->getMessage()]);		# write log
    echo "<p style='color: red;'>An error occurred while loading contents. Please try again later.</p>";	# error mex
    return;
}
?>

<h3>Music Lyrics Repository</h3>
<p>Browse through your secure synchronized music tracks metadata repository.</p>

<table class="lyrics-table">
    <thead>
        <tr>
            <th>Title</th>
            <th>Artist</th>
            <th>Type</th>
            <th>Uploaded At</th>
            <th>Actions</th>
        </tr>
    </thead>
    <tbody>
        <?php if ($result->num_rows === 0): ?>
            <tr>
                <td colspan="5" style="text-align: center; color: #7f8c8d;">No lyrics available in the database.</td>
            </tr>
        <?php else: ?>
            <?php while ($row = $result->fetch_assoc()): ?>
                <tr>
                    <td><?php echo htmlspecialchars($row['title'], ENT_QUOTES, 'UTF-8'); ?></td>
                    <td><?php echo htmlspecialchars($row['artist'], ENT_QUOTES, 'UTF-8'); ?></td>
                    <td>
                        <?php echo $row['is_premium'] ? '<span class="badge-file-premium">PREMIUM</span>' : '<span>Standard</span>'; ?>
                    </td>
                    <td><?php echo htmlspecialchars($row['created_at'], ENT_QUOTES, 'UTF-8'); ?></td>
                    <td>
                        <a href="dashboard.php?view=lyrics&action=view&id=<?php echo (int)$row['id']; ?>" class="page-link" style="font-size: 12px; padding: 3px 8px;">Read</a>
                    </td>
                </tr>
            <?php endwhile; ?>
        <?php endif; ?>
    </tbody>
</table>

<div class="pagination-container">
    <?php for ($i = 1; $i <= $total_pages; $i++): ?>
        <a href="dashboard.php?view=lyrics&page=<?php echo $i; ?>" 
           class="page-link <?php echo $i === $current_page ? 'active' : ''; ?>">
            <?php echo $i; ?>
        </a>
    <?php endfor; ?>
</div>

<?php $stmt->close(); ?>
