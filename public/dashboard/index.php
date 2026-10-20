<?php
declare(strict_types=1);

// Private market dashboard. The password hash and the game data live in ./data,
// which .htaccess closes to the web; both are written by the dashboard-data workflow.

header('X-Robots-Tag: noindex, nofollow');
header('Cache-Control: no-store, max-age=0');
header('Referrer-Policy: same-origin');
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');

const DATA_DIR = __DIR__ . '/data';
const COOKIE_NAME = 'cc_dashboard';
const COOKIE_PATH = '/dashboard';
const COOKIE_DAYS = 30;

function load_json(string $name): ?array
{
    $path = DATA_DIR . '/' . $name;
    if (!is_file($path)) {
        return null;
    }
    $data = json_decode((string) file_get_contents($path), true);
    return is_array($data) ? $data : null;
}

function auth_ready(?array $auth): bool
{
    return $auth !== null
        && ($auth['algo'] ?? '') === 'pbkdf2_sha256'
        && ctype_xdigit((string) ($auth['salt'] ?? ''))
        && ctype_xdigit((string) ($auth['hash'] ?? ''))
        && (int) ($auth['iterations'] ?? 0) > 0;
}

function cookie_key(array $auth): string
{
    return hash_hmac('sha256', 'dashboard-cookie', (string) hex2bin($auth['hash']));
}

function is_https(): bool
{
    return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https')
        || ((int) ($_SERVER['SERVER_PORT'] ?? 0) === 443);
}

function write_cookie(string $value, int $expires): void
{
    setcookie(COOKIE_NAME, $value, [
        'expires' => $expires,
        'path' => COOKIE_PATH,
        'secure' => is_https(),
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
}

function signed_in(array $auth): bool
{
    $value = (string) ($_COOKIE[COOKIE_NAME] ?? '');
    if (!preg_match('/^(\d{1,12})\.([0-9a-f]{64})$/', $value, $m)) {
        return false;
    }
    if ((int) $m[1] < time()) {
        return false;
    }
    return hash_equals(hash_hmac('sha256', $m[1], cookie_key($auth)), $m[2]);
}

function password_matches(array $auth, string $password): bool
{
    $calc = hash_pbkdf2('sha256', $password, (string) hex2bin($auth['salt']), (int) $auth['iterations'], 32, true);
    return hash_equals((string) hex2bin($auth['hash']), $calc);
}

function redirect_here(): void
{
    header('Location: ' . COOKIE_PATH . '/', true, 303);
    exit;
}

function e(string $text): string
{
    return htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

$auth = load_json('auth.json');
$ready = auth_ready($auth);
$error = '';

if (isset($_GET['logout'])) {
    write_cookie('', time() - 3600);
    redirect_here();
}

if ($ready && ($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    $password = (string) ($_POST['password'] ?? '');
    if ($password !== '' && strlen($password) <= 256 && password_matches($auth, $password)) {
        $expires = time() + COOKIE_DAYS * 86400;
        write_cookie($expires . '.' . hash_hmac('sha256', (string) $expires, cookie_key($auth)), $expires);
        redirect_here();
    }
    sleep(1);
    $error = 'Wrong password.';
}

$authed = $ready && signed_in($auth);
$data = $authed ? load_json('games.json') : null;
$json = $data === null ? 'null' : json_encode($data, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE);
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="robots" content="noindex, nofollow">
  <title>Dashboard · Carbon and Capital</title>
  <style>
    @font-face{font-family:"Bebas Neue";font-style:normal;font-weight:400;font-display:swap;src:url("../fonts/bebas-neue-latin.woff2") format("woff2");}
    @font-face{font-family:"IBM Plex Sans Condensed";font-style:normal;font-weight:600;font-display:swap;src:url("../fonts/ibm-plex-sans-condensed-600-latin.woff2") format("woff2");}
    :root{
      --bg:#040f1b;
      --panel:#071a2e;
      --panel-raised:#0b2239;
      --ink:#fdfcf7;
      --cream:#feedc3;
      --gold:#e6b34a;
      --rule:rgba(230,179,74,.34);
      --rule-soft:rgba(254,237,195,.12);
      --font-display:"Bebas Neue","Arial Narrow",sans-serif;
      --font-body:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
      --font-ui:"IBM Plex Sans Condensed","Arial Narrow",sans-serif;
    }
    *{box-sizing:border-box;}
    html{background:var(--bg);}
    body{
      margin:0;min-height:100svh;color:var(--ink);
      background:linear-gradient(rgba(4,15,27,.92),rgba(4,15,27,.97)),url("../hex-tile.png") repeat;
      background-size:auto,460px auto;
      font-family:var(--font-body);line-height:1.5;-webkit-font-smoothing:antialiased;
    }
    a{color:var(--cream);text-decoration-color:rgba(230,179,74,.6);text-underline-offset:.2em;}
    a:hover{color:#fff5d8;}
    .site-header{width:min(1240px,calc(100% - 2rem));margin:0 auto;padding:1.15rem 0;display:flex;align-items:center;justify-content:space-between;gap:1rem;}
    .brand{color:var(--ink);font-family:var(--font-display);font-size:1.45rem;letter-spacing:.055em;text-decoration:none;display:inline-flex;align-items:center;gap:.34em;line-height:1;}
    .brand-and{position:relative;padding:0 .16em .28em;color:var(--gold);font-size:.62em;letter-spacing:.025em;text-transform:lowercase;}
    .brand-and::after{content:"";position:absolute;left:0;right:0;bottom:0;height:2px;border-radius:2px;background:var(--gold);}
    .site-nav a{font-family:var(--font-ui);font-size:.96rem;color:var(--cream);}
    main{width:min(1240px,calc(100% - 2rem));margin:0 auto;padding:1rem 0 4rem;}
    h1{font-family:var(--font-display);font-weight:400;font-size:clamp(2.2rem,5vw,3.2rem);letter-spacing:.04em;line-height:1;margin:.4rem 0 .5rem;}
    h2{font-family:var(--font-display);font-weight:400;font-size:1.9rem;letter-spacing:.05em;margin:2.4rem 0 .2rem;color:var(--cream);}
    h2 .count{color:var(--gold);font-size:.7em;margin-left:.35em;}
    .meta{font-family:var(--font-ui);color:var(--cream);margin:0;font-size:.98rem;}
    .note{color:var(--cream);opacity:.85;font-size:.9rem;margin:.35rem 0 .9rem;}
    .table-wrap{overflow-x:auto;border:1px solid var(--rule);border-radius:10px;background:rgba(7,26,46,.92);}
    table{width:100%;border-collapse:collapse;font-size:.94rem;}
    th,td{padding:.62rem .8rem;text-align:right;white-space:nowrap;border-bottom:1px solid var(--rule-soft);}
    th:first-child,td:first-child{text-align:left;}
    tbody tr:last-child td{border-bottom:0;}
    tbody tr:hover td{background:rgba(11,34,57,.9);}
    thead th{position:sticky;top:0;background:var(--panel-raised);font-family:var(--font-ui);font-weight:600;color:var(--cream);letter-spacing:.02em;}
    th button{all:unset;cursor:pointer;display:inline-flex;align-items:center;gap:.3em;}
    th button:focus-visible{outline:2px solid var(--gold);outline-offset:3px;border-radius:2px;}
    th button::after{content:"";width:.6em;color:var(--gold);}
    th[aria-sort="ascending"] button::after{content:"\25B2";font-size:.7em;}
    th[aria-sort="descending"] button::after{content:"\25BC";font-size:.7em;}
    td.num{font-variant-numeric:tabular-nums;}
    .game{display:flex;align-items:center;gap:.75rem;min-width:15rem;}
    .game img{width:92px;height:43px;object-fit:cover;border-radius:4px;flex:none;background:var(--panel-raised);}
    .game .name{font-weight:600;}
    .game .dev{display:block;color:var(--cream);opacity:.8;font-size:.82rem;}
    .tag{display:inline-block;margin-left:.45em;padding:.05em .45em;border:1px solid var(--gold);border-radius:999px;color:var(--gold);font-family:var(--font-ui);font-size:.74rem;letter-spacing:.03em;vertical-align:1px;}
    .muted{color:var(--cream);opacity:.6;}
    .empty{padding:1.2rem;color:var(--cream);}
    .login{min-height:calc(100svh - 5rem);display:grid;place-items:center;padding:1rem;}
    .card{width:min(380px,100%);padding:2rem 1.75rem;border:1px solid var(--rule);border-radius:14px;background:rgba(7,26,46,.95);box-shadow:0 18px 40px rgba(0,0,0,.45);}
    .card h1{font-size:2.4rem;margin-top:0;}
    .card label{display:block;font-family:var(--font-ui);color:var(--cream);margin:1rem 0 .4rem;}
    .card input{width:100%;padding:.7rem .8rem;font:inherit;color:var(--ink);background:var(--bg);border:1px solid var(--rule);border-radius:8px;}
    .card input:focus{outline:2px solid var(--gold);outline-offset:1px;}
    .card button{margin-top:1rem;width:100%;padding:.75rem;font-family:var(--font-ui);font-size:1rem;letter-spacing:.03em;color:var(--bg);background:var(--gold);border:0;border-radius:8px;cursor:pointer;}
    .card button:hover{background:#f0c360;}
    .error{color:#ffb4a8;margin:.8rem 0 0;font-size:.95rem;}
    footer{width:min(1240px,calc(100% - 2rem));margin:0 auto;padding:0 0 2rem;color:var(--cream);opacity:.7;font-size:.85rem;}
    @media (max-width:640px){
      .site-header{padding:.9rem 0;}
      h2{font-size:1.6rem;}
      th,td{padding:.55rem .6rem;}
      .game img{display:none;}
      .game{min-width:0;width:8.5rem;}
      td:first-child{white-space:normal;}
      th:first-child,td:first-child{position:sticky;left:0;z-index:1;background:var(--panel);box-shadow:1px 0 0 var(--rule-soft);}
      thead th:first-child{z-index:2;background:var(--panel-raised);}
      .tag{display:block;width:max-content;margin:.2em 0 0;}
    }
  </style>
</head>
<body>
  <header class="site-header">
    <a class="brand" href="../"><span>Carbon</span><span class="brand-and">and</span><span>Capital</span></a>
    <?php if ($authed): ?>
    <nav class="site-nav" aria-label="Dashboard"><a href="?logout=1">Sign out</a></nav>
    <?php endif; ?>
  </header>

<?php if (!$authed): ?>
  <main class="login">
    <form class="card" method="post" action="<?= e(COOKIE_PATH) ?>/">
      <h1>Dashboard</h1>
      <?php if (!$ready): ?>
        <p class="note">The dashboard is not set up yet.</p>
      <?php else: ?>
        <label for="password">Password</label>
        <input id="password" name="password" type="password" autocomplete="current-password" required autofocus>
        <button type="submit">Enter</button>
        <?php if ($error !== ''): ?><p class="error" role="alert"><?= e($error) ?></p><?php endif; ?>
      <?php endif; ?>
    </form>
  </main>
<?php else: ?>
  <main>
    <h1>Comparable games</h1>
    <p class="meta" id="updated">No data yet.</p>
    <p class="note">Units, revenue and wishlists are GameOracle estimates, not Steam figures. Hover an estimate for its range.</p>

    <h2>Released <span class="count" id="released-count"></span></h2>
    <div class="table-wrap">
      <table id="released">
        <thead><tr>
          <th scope="col" data-key="title" data-type="text"><button type="button">Game</button></th>
          <th scope="col" data-key="release" data-type="num"><button type="button">Released</button></th>
          <th scope="col" data-key="price" data-type="num"><button type="button">Price</button></th>
          <th scope="col" data-key="reviews" data-type="num"><button type="button">Reviews</button></th>
          <th scope="col" data-key="positive" data-type="num"><button type="button">Positive</button></th>
          <th scope="col" data-key="units" data-type="num"><button type="button">Est. units</button></th>
          <th scope="col" data-key="revenue" data-type="num"><button type="button">Est. revenue</button></th>
          <th scope="col" data-key="wishlists" data-type="num"><button type="button">Est. wishlists</button></th>
          <th scope="col" data-key="followers" data-type="num"><button type="button">Followers</button></th>
        </tr></thead>
        <tbody></tbody>
      </table>
    </div>

    <h2>Unreleased <span class="count" id="unreleased-count"></span></h2>
    <div class="table-wrap">
      <table id="unreleased">
        <thead><tr>
          <th scope="col" data-key="title" data-type="text"><button type="button">Game</button></th>
          <th scope="col" data-key="release" data-type="num"><button type="button">Release</button></th>
          <th scope="col" data-key="wishlists" data-type="num"><button type="button">Est. wishlists</button></th>
          <th scope="col" data-key="followers" data-type="num"><button type="button">Followers</button></th>
        </tr></thead>
        <tbody></tbody>
      </table>
    </div>
  </main>
  <footer>Data from GameOracle. Refreshed daily.</footer>

  <script type="application/json" id="dashboard-data"><?= $json ?></script>
  <script>
  (function () {
    var data = JSON.parse(document.getElementById('dashboard-data').textContent || 'null');
    if (!data || !data.games) return;

    var now = new Date();
    var MONTHS = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
    var countFmt = new Intl.NumberFormat('en-GB');
    var compactFmt = new Intl.NumberFormat('en-GB', {notation: 'compact', maximumFractionDigits: 1});

    function num(v) { return typeof v === 'number' && isFinite(v) ? v : null; }
    function est(v) { return v < 1000 ? countFmt.format(Math.round(v)) : compactFmt.format(v); }
    function monthsSince(d) { return (now.getFullYear() - d.getFullYear()) * 12 + (now.getMonth() - d.getMonth()); }
    function el(tag, cls, text) {
      var n = document.createElement(tag);
      if (cls) n.className = cls;
      if (text != null) n.textContent = text;
      return n;
    }
    function dash() { return el('span', 'muted', '–'); }

    function releasedLabel(g) {
      if (!g.release_date) return g.release_year ? String(g.release_year) : null;
      var d = new Date(g.release_date);
      if (isNaN(d)) return null;
      return monthsSince(d) < 12 ? MONTHS[d.getUTCMonth()] + ' ' + d.getUTCFullYear() : String(d.getUTCFullYear());
    }
    function upcomingLabel(g) {
      if (g.release_date) {
        var d = new Date(g.release_date);
        if (!isNaN(d)) return MONTHS[d.getUTCMonth()] + ' ' + d.getUTCFullYear();
      }
      if (g.release_quarter && g.release_year) return 'Q' + g.release_quarter + ' ' + g.release_year;
      if (g.release_year) return String(g.release_year);
      return 'TBA';
    }
    function releaseSort(g) {
      if (g.release_date) { var t = Date.parse(g.release_date); if (!isNaN(t)) return t; }
      if (g.release_year) return Date.UTC(g.release_year, ((g.release_quarter || 4) * 3) - 1, 28);
      return null;
    }

    function gameCell(g) {
      var td = el('td');
      var wrap = el('div', 'game');
      if (g.capsule) {
        var img = el('img');
        img.src = g.capsule; img.alt = ''; img.loading = 'lazy'; img.width = 92; img.height = 43;
        wrap.appendChild(img);
      }
      var text = el('div');
      var a = el('a', 'name', g.title || ('App ' + g.app_id));
      a.href = 'https://store.steampowered.com/app/' + g.app_id + '/';
      a.target = '_blank'; a.rel = 'noopener';
      text.appendChild(a);
      if (g.early_access) text.appendChild(el('span', 'tag', g.coming_soon ? 'Early access launch' : 'Early access'));
      var who = (g.developers || []).join(', ');
      if (who) text.appendChild(el('span', 'dev', who));
      wrap.appendChild(text);
      td.appendChild(wrap);
      return td;
    }
    function numCell(value, text, title) {
      var td = el('td', 'num');
      if (value == null) td.appendChild(dash()); else td.textContent = text;
      if (title) td.title = title;
      return td;
    }
    function textCell(text) {
      var td = el('td');
      if (text == null) td.appendChild(dash()); else td.textContent = text;
      return td;
    }

    function releasedRow(g) {
      var tr = el('tr');
      var units = num(g.units), revenue = num(g.revenue), wish = num(g.wishlists);
      var range = num(g.units_low) != null && num(g.units_high) != null
        ? 'Range ' + countFmt.format(Math.round(g.units_low)) + ' to ' + countFmt.format(Math.round(g.units_high)) : '';
      tr.appendChild(gameCell(g));
      tr.appendChild(textCell(releasedLabel(g)));
      tr.appendChild(numCell(g.is_free ? 0 : num(g.price), g.is_free ? 'Free' : '$' + Number(g.price).toFixed(2)));
      tr.appendChild(numCell(num(g.reviews), countFmt.format(g.reviews || 0)));
      tr.appendChild(numCell(num(g.positive), Math.round(g.positive) + '%'));
      tr.appendChild(numCell(units, '~' + est(units), range));
      tr.appendChild(numCell(revenue, '~$' + est(revenue)));
      tr.appendChild(numCell(wish, '~' + est(wish)));
      tr.appendChild(numCell(num(g.followers), countFmt.format(g.followers || 0)));
      tr._sort = {title: (g.title || '').toLowerCase(), release: releaseSort(g), price: g.is_free ? 0 : num(g.price),
        reviews: num(g.reviews), positive: num(g.positive), units: units, revenue: revenue, wishlists: wish, followers: num(g.followers)};
      return tr;
    }
    function unreleasedRow(g) {
      var tr = el('tr');
      var wish = num(g.wishlists);
      tr.appendChild(gameCell(g));
      tr.appendChild(textCell(upcomingLabel(g)));
      tr.appendChild(numCell(wish, '~' + est(wish)));
      tr.appendChild(numCell(num(g.followers), countFmt.format(g.followers || 0)));
      tr._sort = {title: (g.title || '').toLowerCase(), release: releaseSort(g), wishlists: wish, followers: num(g.followers)};
      return tr;
    }

    function fill(tableId, games, rowFn, defaultKey) {
      var table = document.getElementById(tableId);
      var body = table.tBodies[0];
      var rows = games.map(rowFn);
      if (!rows.length) {
        var tr = el('tr'), td = el('td', 'empty', 'None right now.');
        td.colSpan = table.tHead.rows[0].cells.length;
        tr.appendChild(td); body.appendChild(tr);
        return;
      }
      function sortBy(key, dir) {
        rows.sort(function (a, b) {
          var x = a._sort[key], y = b._sort[key];
          if (x == null && y == null) return 0;
          if (x == null) return 1;
          if (y == null) return -1;
          return (x < y ? -1 : x > y ? 1 : 0) * dir;
        });
        rows.forEach(function (r) { body.appendChild(r); });
        Array.prototype.forEach.call(table.tHead.rows[0].cells, function (th) {
          if (th.dataset.key === key) th.setAttribute('aria-sort', dir > 0 ? 'ascending' : 'descending');
          else th.removeAttribute('aria-sort');
        });
      }
      Array.prototype.forEach.call(table.tHead.rows[0].cells, function (th) {
        th.querySelector('button').addEventListener('click', function () {
          var current = th.getAttribute('aria-sort');
          var dir = current === 'descending' ? 1 : current === 'ascending' ? -1 : (th.dataset.type === 'text' ? 1 : -1);
          sortBy(th.dataset.key, dir);
        });
      });
      sortBy(defaultKey, -1);
    }

    var games = data.games.filter(function (g) { return !g.missing; });
    var released = games.filter(function (g) { return !g.coming_soon; });
    var unreleased = games.filter(function (g) { return g.coming_soon; });
    document.getElementById('released-count').textContent = released.length;
    document.getElementById('unreleased-count').textContent = unreleased.length;
    fill('released', released, releasedRow, 'units');
    fill('unreleased', unreleased, unreleasedRow, 'wishlists');

    var when = new Date(data.fetched_at);
    if (!isNaN(when)) {
      document.getElementById('updated').textContent = 'Updated ' + when.toLocaleString('en-GB', {day: 'numeric', month: 'long', year: 'numeric', hour: '2-digit', minute: '2-digit'});
    }
    var missing = data.games.filter(function (g) { return g.missing; });
    if (missing.length) {
      var p = el('p', 'note', 'Not found in GameOracle: ' + missing.map(function (g) { return g.title || g.app_id; }).join(', ') + '.');
      document.querySelector('main').appendChild(p);
    }
  })();
  </script>
<?php endif; ?>
</body>
</html>
