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
    die("<p style='color:orange; font-family:monospace;'>[DEBUG] Errore: \$conn è NULL nel modulo lyrics!</p>");
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
            echo "<p style='color: red; font-weight: bold;'>Content not found or access denied.</p>";
            echo '<p><a href="dashboard.php?view=lyrics" class="page-link">&laquo; Back to List</a></p>';
            return;
        }
        // -- end this part of php and start html code --
        ?>
        
        <div class="lyric-view-container" style="background: #fafafa; padding: 20px; border-radius: 5px; border: 1px solid #ddd; margin-top: 15px;">
            <h2 style="margin-top: 0; color: #2b7a78;"><?php echo htmlspecialchars($lyric_data['title'], ENT_QUOTES, 'UTF-8'); ?></h2>
            <p style="font-style: italic; color: #555;">By <?php echo htmlspecialchars($lyric_data['author'], ENT_QUOTES, 'UTF-8'); ?></p>
            <hr style="border: 0; border-top: 1px solid #eee; margin: 15px 0;">
            
            <div class="lyric-content" style="white-space: pre-wrap; font-family: monospace; line-height: 1.6; background: white; padding: 15px; border: 1px dashed #ccc;">
                <?php 
                    echo isset($lyric_data['content']) ? htmlspecialchars($lyric_data['content'], ENT_QUOTES, 'UTF-8') : "[Text Content Display Placeholder] Secure metadata loaded successfully."; 
                ?>
            </div>
            
            <p style="margin-top: 20px;">
                <a href="dashboard.php?view=lyrics" class="page-link" style="padding: 8px 15px;">&laquo; Back to Lyrics Repository</a>
            </p>
        </div>

        <?php
        // -- restart this part of php and end html code --
    } catch (Throwable $e) {
        $securityLogger->error("Error rendering lyric single view", ["error" => $e->getMessage()]);
        echo "<p style='color: red;'>An error occurred while opening the lyric.</p>";
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
$offset = ($current_page - 1) * $records_per_page;	# offset indicate the number of lyrics of the pas page (if sum to current index get the total index)

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
    $securityLogger->error("Database error inside lyrics submodule", ["error" => $e->getMessage()]);		# write log
    echo "<p style='color: red;'>An error occurred while loading contents. Please try again later.</p>";	# error mex
    return;
}
?>

<div style="margin-bottom: 20px;">
    <h3 style="margin: 0 0 5px 0; color: #17252a; font-size: 20px; font-weight: bold;">Music Lyrics Repository</h3>
    <span style="color: #64748b; font-size: 14px;">Browse through your secure synchronized music tracks metadata repository.</span>
</div>

<table class="lyrics-table" style="width: 100%; border-collapse: separate; border-spacing: 0; margin-top: 10px; table-layout: fixed; border: 1px solid #cbd5e1; border-radius: 6px; overflow: hidden;">
    <thead>
        <tr style="background-color: #f8fafc;">
            <th style="width: 35%; text-align: left; padding: 12px 15px; border-bottom: 2px solid #cbd5e1; color: #334155; font-weight: 600;">Title</th>
            <th style="width: 25%; text-align: left; padding: 12px 15px; border-bottom: 2px solid #cbd5e1; color: #334155; font-weight: 600;">Author</th>
            <th style="width: 15%; text-align: left; padding: 12px 15px; border-bottom: 2px solid #cbd5e1; color: #334155; font-weight: 600;">Type</th>
            <th style="width: 15%; text-align: left; padding: 12px 15px; border-bottom: 2px solid #cbd5e1; color: #334155; font-weight: 600;">Uploaded At</th>
            <th style="width: 10%; text-align: center; padding: 12px 15px; border-bottom: 2px solid #cbd5e1; color: #334155; font-weight: 600;">Actions</th>
        </tr>
    </thead>
    <tbody>
        <?php if ($result->num_rows === 0): ?>
            <tr>
                <td colspan="5" style="text-align: center; padding: 30px; color: #64748b; background-color: #ffffff;">No lyrics available in the database.</td>
            </tr>
        <?php else: ?>
            <?php 
            $cnt = 0;
            while ($row = $result->fetch_assoc()): 
                $cnt++;
                // Effetto zebra-striping alternando il background delle righe
                $bg_color = ($cnt % 2 === 0) ? '#f8fafc' : '#ffffff';
                // Rimuoviamo il bordo inferiore all'ultima riga della tabella
                $border_bottom = ($cnt === $result->num_rows) ? 'none' : '1px solid #e2e8f0';
            ?>
                <tr style="background-color: <?php echo $bg_color; ?>; transition: background 0.15s;">
                    <td style="padding: 12px 15px; border-bottom: <?php echo $border_bottom; ?>; color: #0f172a; font-weight: 500; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                        <?php echo htmlspecialchars($row['title'], ENT_QUOTES, 'UTF-8'); ?>
                    </td>
                    <td style="padding: 12px 15px; border-bottom: <?php echo $border_bottom; ?>; color: #334155; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                        <?php echo htmlspecialchars($row['author'], ENT_QUOTES, 'UTF-8'); ?>
                    </td>
                    <td style="padding: 12px 15px; border-bottom: <?php echo $border_bottom; ?>;">
                        <?php echo $row['is_premium'] ? '<span class="badge-file-premium">PREMIUM</span>' : '<span style="background: #e2e8f0; color: #334155; padding: 2px 6px; font-size: 11px; font-weight: bold; border-radius: 3px;">STANDARD</span>'; ?>
                    </td>
                    <td style="padding: 12px 15px; border-bottom: <?php echo $border_bottom; ?>; color: #64748b; font-size: 13px;">
                        <?php echo htmlspecialchars($row['created_at'], ENT_QUOTES, 'UTF-8'); ?>
                    </td>
                    <td style="padding: 12px 15px; border-bottom: <?php echo $border_bottom; ?>; text-align: center;">
                        <a href="dashboard.php?view=lyrics&action=view&id=<?php echo (int)$row['id']; ?>" class="page-link" style="font-size: 12px; padding: 4px 10px; display: inline-block;">Read</a>
                    </td>
                </tr>
            <?php endwhile; ?>
        <?php endif; ?>
    </tbody>
</table>

<div class="pagination-container" style="margin-top: 25px; display: flex; justify-content: center; gap: 8px; width: 100%;">
    <?php
    	// visualize the link for the lyrics pages only if there are more than 1 page 
    	if ($total_pages > 1): 
    ?>
        <?php for ($i = 1; $i <= $total_pages; $i++): ?>
            <a href="dashboard.php?view=lyrics&page=<?php echo $i; ?>" 
               class="page-link <?php echo $i === $current_page ? 'active' : ''; ?>"
               style="padding: 6px 12px; border-radius: 4px; min-width: 15px; text-align: center;">
                <?php echo $i; ?>
            </a>
        <?php endfor; ?>
    <?php endif; ?>
</div>

<?php $stmt->close(); ?>
