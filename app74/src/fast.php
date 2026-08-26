<?php
// Legacy-style physical endpoint (no front controller): apache2handler
// keeps request_info.request_uri = /fast.php, so the tracer sees per-endpoint URIs.
$_SERVER["REQUEST_URI"] = "/fast";
require "/var/www/shared/index.php";
