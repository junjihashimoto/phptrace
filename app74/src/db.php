<?php
// Legacy-style physical endpoint (no front controller): apache2handler
// keeps request_info.request_uri = /db.php, so the tracer sees per-endpoint URIs.
$_SERVER["REQUEST_URI"] = "/db";
require "/var/www/shared/index.php";
