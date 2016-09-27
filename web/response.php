<?php
if ($_POST) {
    echo "<table border=\"2\" cellpadding=\"2\">";

    echo "<tr><td>Name</td><td>Value</td></tr>";

	foreach ($_POST as $key => $val) {
		echo "<tr><td>$key</td><td>$val</td></tr>";
	}

    echo "</table>";
} else {
	echo "<h2>No data found</h2>";
}
?>

