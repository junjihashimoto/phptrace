<?php
// Legacy-style physical endpoint (no front controller): apache2handler
// keeps request_info.request_uri = /slow.php, so the tracer sees per-endpoint URIs.
$_SERVER["REQUEST_URI"] = "/slow";
require "/var/www/shared/index.php";
