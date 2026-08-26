<?php
declare(strict_types=1);

/**
 * Demo app for the eBPF tracer. Endpoints exercise distinct latency
 * profiles so flamegraphs / percentiles have something to show:
 *   /fast  - immediate response
 *   /slow  - sleep-dominated (off-CPU)
 *   /db    - MySQL queries via PDO (mysqlnd boundary probe target)
 *   /cpu   - on-CPU recursion + hashing (sampler target)
 *   /mixed - all of the above
 * Deliberately deep Class::method call chains: the sampler resolves
 * zend_function pointers, so give it recognizable names.
 */

final class Database
{
    private static ?PDO $pdo = null;

    public static function get(): PDO
    {
        if (self::$pdo === null) {
            self::$pdo = new PDO(
                getenv('DB_DSN') ?: 'mysql:host=mysql;dbname=demo',
                getenv('DB_USER') ?: 'demo',
                getenv('DB_PASS') ?: 'demo',
                [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
            );
        }
        return self::$pdo;
    }
}

final class UserRepository
{
    public function findProfile(int $userId): ?array
    {
        $stmt = Database::get()->prepare(
            'SELECT * FROM profile_info WHERE user_id = ?'
        );
        $stmt->execute([$userId]);
        return $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
    }

    public function recentActivity(int $limit): array
    {
        $stmt = Database::get()->query(
            "SELECT user_id, COUNT(*) c FROM profile_info GROUP BY user_id ORDER BY c DESC LIMIT $limit"
        );
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function logAction(int $userId, string $action): void
    {
        $stmt = Database::get()->prepare(
            'INSERT INTO activity_log (user_id, action) VALUES (?, ?)'
        );
        $stmt->execute([$userId, $action]);
    }
}

final class Fibonacci
{
    public static function compute(int $n): int
    {
        return $n < 2 ? $n : self::compute($n - 1) + self::compute($n - 2);
    }
}

final class HashService
{
    public function digest(string $seed, int $rounds): string
    {
        $h = $seed;
        for ($i = 0; $i < $rounds; $i++) {
            $h = hash('sha256', $h . $i);
        }
        return $h;
    }
}

final class TemplateEngine
{
    public function render(string $name, array $vars): string
    {
        $this->simulateIo();
        return json_encode(['template' => $name, 'vars' => $vars]);
    }

    private function simulateIo(): void
    {
        usleep(random_int(20_000, 120_000));
    }
}

final class FastController
{
    public function handle(): array
    {
        return ['status' => 'ok', 'ts' => microtime(true)];
    }
}

final class SlowController
{
    public function handle(): array
    {
        $body = (new TemplateEngine())->render('profile', ['theme' => 'dark']);
        return ['status' => 'ok', 'rendered' => strlen($body)];
    }
}

final class DbController
{
    public function handle(): array
    {
        $repo = new UserRepository();
        $userId = random_int(0, 999) * 1000 + 48909;
        $profile = $repo->findProfile($userId);
        $activity = $repo->recentActivity(10);
        $repo->logAction($userId, 'view');
        return ['status' => 'ok', 'found' => $profile !== null, 'top' => count($activity)];
    }
}

final class CpuController
{
    public function handle(): array
    {
        $fib = Fibonacci::compute(random_int(20, 24));
        $digest = (new HashService())->digest('seed', random_int(5_000, 20_000));
        return ['status' => 'ok', 'fib' => $fib, 'digest' => substr($digest, 0, 8)];
    }
}

final class MixedController
{
    public function handle(): array
    {
        $db = (new DbController())->handle();
        $cpu = (new CpuController())->handle();
        usleep(random_int(5_000, 30_000));
        return ['status' => 'ok', 'db' => $db, 'cpu' => $cpu];
    }
}

/**
 * Realistic web request: several DB queries + moderate compute + template
 * render + a bit of I/O wait. Tuned to land in the ~50-150ms band typical of
 * a real controller (mostly DB/IO-bound, i.e. off-CPU), unlike /fast (noop)
 * or /cpu (100% on-CPU). This is the honest endpoint for overhead numbers.
 */
final class ApiController
{
    public function handle(): array
    {
        $repo = new UserRepository();
        // a handful of DB round-trips (small, but real off-CPU query time)
        for ($i = 0; $i < 5; $i++) {
            $userId = random_int(0, 999) * 1000 + 48909;
            $repo->findProfile($userId);
            $repo->recentActivity(5);
        }
        $repo->logAction(random_int(0, 999) * 1000 + 48909, 'api');
        // one upstream/template I/O wait (the dominant, off-CPU cost) ~40-100ms
        $body = (new TemplateEngine())->render('api', ['n' => 5]);
        // modest CPU on top (serialization/formatting-ish)
        (new HashService())->digest('api', random_int(2_000, 6_000));
        return ['status' => 'ok', 'rows' => 5, 'rendered' => strlen($body)];
    }
}

/* ---- framework-shaped request: DB/IO-bound (~100ms) BUT with thousands of
 * cheap *userland* calls (autoload / DI / ORM hydration / events), like a real
 * Symfony/Laravel request. This is the honest worst-realistic case for
 * per-call tracing: latency is dominated by off-CPU waits, yet execute_ex
 * fires thousands of times per request (frameworks are call-dense). The 2024
 * production trace showed exactly this (I18n autoload, ClassLoader::load
 * called en masse). Individual calls are cheap so wall-time stays realistic. */
final class Autoloader
{
    public function load(string $class): void { $this->resolve($class, 3); }
    private function resolve(string $c, int $d): void
    {
        if ($d <= 0) return;
        $this->normalize($c);
        $this->resolve($c, $d - 1);
    }
    private function normalize(string $c): string { return strtolower($c); }
}
final class Service
{
    public function __construct(public string $id) {}
    public function run(): int { return strlen($this->id); }
}
final class Container
{
    private array $svc = [];
    public function get(string $id): Service { return $this->svc[$id] ??= $this->build($id); }
    private function build(string $id): Service { return new Service($id); }
}
final class Entity
{
    private array $data = [];
    public function set(string $k, $v): self { $this->data[$k] = $this->cast($v); return $this; }
    public function get(string $k) { return $this->data[$k] ?? null; }
    private function cast($v) { return is_numeric($v) ? (int) $v : (string) $v; }
}
final class Hydrator
{
    public function hydrate(array $row): Entity
    {
        $e = new Entity();
        foreach ($row as $k => $v) { $e->set((string) $k, $v); } // userland set()/cast() per column
        return $e;
    }
}
final class EventDispatcher
{
    private array $listeners = [];
    public function on(string $e, callable $l): void { $this->listeners[$e][] = $l; }
    public function dispatch(string $e, $p): void
    {
        foreach ($this->listeners[$e] ?? [] as $l) { $l($p); } // userland listener calls
    }
}
final class FrameworkController
{
    public function handle(): array
    {
        $al = new Autoloader();
        $c  = new Container();
        $hy = new Hydrator();
        $ev = new EventDispatcher();
        $ev->on('hydrated', fn(Entity $e) => $e->get('user_id'));
        // "boot": resolve/autoload ~40 services (each = several userland calls)
        for ($i = 0; $i < 40; $i++) { $al->load("App\\Service{$i}"); $c->get("svc{$i}")->run(); }

        $repo = new UserRepository();
        $n = 0;
        for ($q = 0; $q < 5; $q++) {            // 5 DB round-trips (I/O, off-CPU)
            foreach ($repo->recentActivity(20) as $row) {
                $e = $hy->hydrate($row);        // userland set()/cast() per column
                $ev->dispatch('hydrated', $e);  // userland listener
                $n++;
            }
        }
        // one upstream/template I/O wait (dominant off-CPU cost, ~20-120ms)
        (new TemplateEngine())->render('fw', ['n' => $n]);
        return ['status' => 'ok', 'entities' => $n];
    }
}

final class Router
{
    // switch, not match: this file also runs on the PHP 7.4 legacy stack
    public function dispatch(string $path): array
    {
        switch ($path) {
            case '/fast':  return (new FastController())->handle();
            case '/slow':  return (new SlowController())->handle();
            case '/db':    return (new DbController())->handle();
            case '/cpu':   return (new CpuController())->handle();
            case '/mixed': return (new MixedController())->handle();
            case '/api':   return (new ApiController())->handle();
            case '/framework': return (new FrameworkController())->handle();
            case '/':      return ['endpoints' => ['/fast', '/slow', '/db', '/cpu', '/mixed', '/api', '/framework']];
            default:       return ['error' => 'not found'];
        }
    }
}

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
try {
    $result = (new Router())->dispatch($path);
    http_response_code(isset($result['error']) ? 404 : 200);
} catch (Throwable $e) {
    http_response_code(500);
    $result = ['error' => $e->getMessage()];
}
header('Content-Type: application/json');
echo json_encode($result), "\n";
