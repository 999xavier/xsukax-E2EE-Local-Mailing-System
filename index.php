<?php
/**
 * xsukax E2EE Local Mailing System - Single File Application
 * Version: 1.0.0
 * Author: xsukax
 * 
 * Complete end-to-end encrypted mailing system in a single PHP file
 * - Zero-knowledge architecture with AES-256-GCM encryption
 * - Works on any domain with nginx or Apache
 * - No configuration required - just upload and run!
 * - Serves both API and web interface from one file
 */

// Error reporting configuration
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/error.log');

// Configuration - Automatically adapts to any domain
define('DB_FILE', __DIR__ . '/xsukax_mail.db');
define('JWT_SECRET', 'xsukax-e2ee-mail-system-' . hash('sha256', __DIR__ . $_SERVER['HTTP_HOST']));
define('DOMAIN', $_SERVER['HTTP_HOST'] ?? 'localhost');
define('VERSION', '1.0.0');

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

function initDatabase() {
    try {
        $db = new PDO('sqlite:' . DB_FILE);
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $db->setAttribute(PDO::ATTR_TIMEOUT, 10);
        $db->exec("PRAGMA journal_mode=WAL");
        $db->exec("PRAGMA synchronous=NORMAL");
        
        $db->exec("
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                domain TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(username, domain)
            )
        ");
        
        $db->exec("
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_user TEXT NOT NULL,
                to_user TEXT NOT NULL,
                subject TEXT NOT NULL,
                encrypted_content TEXT NOT NULL,
                encrypted_attachments TEXT,
                is_deleted INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (from_user) REFERENCES users(email),
                FOREIGN KEY (to_user) REFERENCES users(email)
            )
        ");
        
        $db->exec("CREATE INDEX IF NOT EXISTS idx_messages_to_user ON messages(to_user)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_messages_from_user ON messages(from_user)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_messages_deleted ON messages(is_deleted)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(created_at DESC)");
        
        return $db;
    } catch (PDOException $e) {
        error_log("Database initialization failed: " . $e->getMessage());
        return null;
    }
}

function getDB() {
    static $db = null;
    if ($db === null) {
        $db = initDatabase();
    }
    return $db;
}

function generateJWT($userId, $email) {
    $header = base64_encode(json_encode(['typ' => 'JWT', 'alg' => 'HS256']));
    $payload = base64_encode(json_encode([
        'user_id' => $userId,
        'email' => $email,
        'domain' => DOMAIN,
        'iat' => time(),
        'exp' => time() + (7 * 24 * 60 * 60)
    ]));
    $signature = hash_hmac('sha256', "$header.$payload", JWT_SECRET, true);
    $signature = base64_encode($signature);
    return "$header.$payload.$signature";
}

function verifyJWT($token) {
    $parts = explode('.', $token);
    if (count($parts) !== 3) return false;
    list($header, $payload, $signature) = $parts;
    $validSignature = base64_encode(hash_hmac('sha256', "$header.$payload", JWT_SECRET, true));
    if ($signature !== $validSignature) return false;
    $payloadData = json_decode(base64_decode($payload), true);
    if (!$payloadData || $payloadData['exp'] < time()) return false;
    return $payloadData;
}

function getAuthUser() {
    $headers = getallheaders();
    if (!$headers) $headers = [];
    $authHeader = $headers['Authorization'] ?? $headers['authorization'] ?? '';
    if (!preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) return null;
    return verifyJWT($matches[1]);
}

function validateEmail($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

function sanitizeInput($input) {
    return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
}

function jsonResponse($data, $statusCode = 200) {
    header('Content-Type: application/json; charset=utf-8');
    http_response_code($statusCode);
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit();
}

function errorResponse($message, $statusCode = 400) {
    jsonResponse(['success' => false, 'message' => $message], $statusCode);
}

function successResponse($data = []) {
    jsonResponse(array_merge(['success' => true], $data));
}

// ============================================================================
// ROUTING
// ============================================================================

$requestMethod = $_SERVER['REQUEST_METHOD'];
$isApiRequest = isset($_GET['api']) || isset($_GET['action']);

// ============================================================================
// API HANDLER
// ============================================================================

if ($isApiRequest) {
    // CORS Headers
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');
    header('Access-Control-Max-Age: 3600');
    
    if ($requestMethod === 'OPTIONS') {
        http_response_code(200);
        exit();
    }
    
    $action = $_GET['action'] ?? 'info';
    
    try {
        // GET /info
        if ($action === 'info' && $requestMethod === 'GET') {
            successResponse([
                'domain' => DOMAIN,
                'version' => VERSION,
                'system' => 'xsukax E2EE Local Mailing System',
                'encryption' => 'AES-256-GCM (client-side)',
                'timestamp' => date('c')
            ]);
        }
        
        // POST /register
        elseif ($action === 'register' && $requestMethod === 'POST') {
            $input = json_decode(file_get_contents('php://input'), true);
            if (!$input) errorResponse('Invalid JSON input');
            
            $username = sanitizeInput($input['username'] ?? '');
            $password = $input['password'] ?? '';
            
            if (empty($username) || empty($password)) errorResponse('Username and password are required');
            if (!preg_match('/^[a-zA-Z0-9_-]{3,30}$/', $username)) errorResponse('Username must be 3-30 characters');
            if (strlen($password) < 6) errorResponse('Password must be at least 6 characters');
            
            $email = $username . '@' . DOMAIN;
            $passwordHash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
            
            try {
                $db = getDB();
                $stmt = $db->prepare("INSERT INTO users (username, domain, email, password_hash) VALUES (?, ?, ?, ?)");
                $stmt->execute([$username, DOMAIN, $email, $passwordHash]);
                successResponse(['message' => 'Registration successful', 'email' => $email]);
            } catch (PDOException $e) {
                if (strpos($e->getMessage(), 'UNIQUE constraint failed') !== false) {
                    errorResponse('Username already exists');
                }
                errorResponse('Registration failed', 500);
            }
        }
        
        // POST /login
        elseif ($action === 'login' && $requestMethod === 'POST') {
            $input = json_decode(file_get_contents('php://input'), true);
            if (!$input) errorResponse('Invalid JSON input');
            
            $email = sanitizeInput($input['email'] ?? '');
            $password = $input['password'] ?? '';
            
            if (!validateEmail($email) || empty($password)) errorResponse('Invalid credentials', 401);
            
            $db = getDB();
            $stmt = $db->prepare("SELECT id, email, password_hash, username, domain FROM users WHERE email = ?");
            $stmt->execute([$email]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$user || !password_verify($password, $user['password_hash'])) {
                usleep(500000);
                errorResponse('Invalid credentials', 401);
            }
            
            $token = generateJWT($user['id'], $user['email']);
            successResponse([
                'token' => $token,
                'user' => [
                    'id' => $user['id'],
                    'email' => $user['email'],
                    'username' => $user['username'],
                    'domain' => $user['domain']
                ]
            ]);
        }
        
        // POST /send
        elseif ($action === 'send' && $requestMethod === 'POST') {
            $authUser = getAuthUser();
            if (!$authUser) errorResponse('Unauthorized', 401);
            
            $input = json_decode(file_get_contents('php://input'), true);
            if (!$input) errorResponse('Invalid JSON input');
            
            $to = sanitizeInput($input['to'] ?? '');
            $subject = sanitizeInput($input['subject'] ?? '');
            $encryptedContent = $input['encrypted_content'] ?? '';
            $encryptedAttachments = $input['encrypted_attachments'] ?? null;
            
            if (!validateEmail($to)) errorResponse('Invalid recipient email');
            if (empty($subject) || empty($encryptedContent)) errorResponse('Subject and content are required');
            
            $db = getDB();
            $stmt = $db->prepare("SELECT id FROM users WHERE email = ?");
            $stmt->execute([$to]);
            if (!$stmt->fetch()) errorResponse('Recipient does not exist');
            
            $attachmentsJson = null;
            if ($encryptedAttachments && is_array($encryptedAttachments)) {
                $attachmentsJson = json_encode($encryptedAttachments);
            }
            
            $stmt = $db->prepare("INSERT INTO messages (from_user, to_user, subject, encrypted_content, encrypted_attachments) VALUES (?, ?, ?, ?, ?)");
            $stmt->execute([$authUser['email'], $to, $subject, $encryptedContent, $attachmentsJson]);
            successResponse(['message' => 'Message sent successfully', 'message_id' => $db->lastInsertId()]);
        }
        
        // GET /messages (inbox, sent, or trash)
        elseif ($action === 'messages' && $requestMethod === 'GET') {
            $authUser = getAuthUser();
            if (!$authUser) errorResponse('Unauthorized', 401);
            
            $type = $_GET['type'] ?? 'inbox';
            $db = getDB();
            
            if ($type === 'sent') {
                // Get sent messages
                $stmt = $db->prepare("
                    SELECT id, from_user, to_user, subject, created_at,
                    CASE WHEN encrypted_attachments IS NOT NULL AND encrypted_attachments != '' THEN 
                        (LENGTH(encrypted_attachments) - LENGTH(REPLACE(encrypted_attachments, 'filename', ''))) / LENGTH('filename')
                    ELSE 0 END as attachments_count
                    FROM messages WHERE from_user = ? AND is_deleted = 0 ORDER BY created_at DESC LIMIT 1000
                ");
                $stmt->execute([$authUser['email']]);
            } else {
                // Get inbox or trash messages
                $isDeleted = ($type === 'trash') ? 1 : 0;
                $stmt = $db->prepare("
                    SELECT id, from_user, to_user, subject, created_at,
                    CASE WHEN encrypted_attachments IS NOT NULL AND encrypted_attachments != '' THEN 
                        (LENGTH(encrypted_attachments) - LENGTH(REPLACE(encrypted_attachments, 'filename', ''))) / LENGTH('filename')
                    ELSE 0 END as attachments_count
                    FROM messages WHERE to_user = ? AND is_deleted = ? ORDER BY created_at DESC LIMIT 1000
                ");
                $stmt->execute([$authUser['email'], $isDeleted]);
            }
            
            $messages = $stmt->fetchAll(PDO::FETCH_ASSOC);
            successResponse(['messages' => $messages, 'count' => count($messages), 'type' => $type]);
        }
        
        // GET /message/{id}
        elseif ($action === 'message' && isset($_GET['id']) && $requestMethod === 'GET') {
            $authUser = getAuthUser();
            if (!$authUser) errorResponse('Unauthorized', 401);
            
            $db = getDB();
            $stmt = $db->prepare("SELECT * FROM messages WHERE id = ? AND (to_user = ? OR from_user = ?)");
            $stmt->execute([$_GET['id'], $authUser['email'], $authUser['email']]);
            $message = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$message) errorResponse('Message not found', 404);
            successResponse(['message' => $message]);
        }
        
        // POST /trash - Move message to trash
        elseif ($action === 'trash' && isset($_GET['id']) && $requestMethod === 'POST') {
            $authUser = getAuthUser();
            if (!$authUser) errorResponse('Unauthorized', 401);
            
            $db = getDB();
            $stmt = $db->prepare("UPDATE messages SET is_deleted = 1 WHERE id = ? AND to_user = ? AND is_deleted = 0");
            $stmt->execute([$_GET['id'], $authUser['email']]);
            
            if ($stmt->rowCount() === 0) errorResponse('Message not found', 404);
            successResponse(['message' => 'Message moved to trash']);
        }
        
        // DELETE /delete - Permanently delete message
        elseif ($action === 'delete' && isset($_GET['id']) && $requestMethod === 'DELETE') {
            $authUser = getAuthUser();
            if (!$authUser) errorResponse('Unauthorized', 401);
            
            $db = getDB();
            $stmt = $db->prepare("DELETE FROM messages WHERE id = ? AND to_user = ? AND is_deleted = 1");
            $stmt->execute([$_GET['id'], $authUser['email']]);
            
            if ($stmt->rowCount() === 0) errorResponse('Message not found', 404);
            successResponse(['message' => 'Message deleted permanently']);
        }
        
        else {
            errorResponse("Invalid action: $action", 404);
        }
    } catch (Exception $e) {
        error_log("API Error: " . $e->getMessage());
        errorResponse('Internal server error', 500);
    }
}

// ============================================================================
// WEB INTERFACE
// ============================================================================

// Detect HTTPS - works with nginx, Apache, and proxies
$isHttps = (
    (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ||
    (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') ||
    (isset($_SERVER['HTTP_X_FORWARDED_SSL']) && $_SERVER['HTTP_X_FORWARDED_SSL'] === 'on') ||
    (isset($_SERVER['SERVER_PORT']) && $_SERVER['SERVER_PORT'] == 443)
);
$protocol = $isHttps ? 'https' : 'http';
$currentUrl = $protocol . '://' . $_SERVER['HTTP_HOST'] . $_SERVER['SCRIPT_NAME'];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>xsukax E2EE Local Mailing System</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif; background: #f6f8fa; color: #24292f; }
        .container { max-width: 1280px; margin: 0 auto; padding: 2rem; }
        .card { background: white; border: 1px solid #d0d7de; border-radius: 6px; padding: 1.5rem; margin-bottom: 1rem; box-shadow: 0 1px 3px rgba(0,0,0,0.04); }
        .btn { padding: 0.5rem 1rem; border-radius: 6px; font-weight: 500; cursor: pointer; transition: all 0.2s; border: 1px solid; font-size: 14px; display: inline-flex; align-items: center; justify-content: center; }
        .btn-primary { background: #2da44e; color: white; border-color: rgba(27,31,36,0.15); }
        .btn-primary:hover { background: #2c974b; }
        .btn-secondary { background: #f6f8fa; color: #24292f; border-color: rgba(27,31,36,0.15); }
        .btn-secondary:hover { background: #f3f4f6; }
        .btn-danger { background: #cf222e; color: white; border-color: rgba(27,31,36,0.15); }
        .btn-danger:hover { background: #a40e26; }
        .input { width: 100%; padding: 0.5rem 0.75rem; border: 1px solid #d0d7de; border-radius: 6px; font-size: 14px; background: #ffffff; transition: border-color 0.2s; }
        .input:focus { outline: none; border-color: #0969da; box-shadow: 0 0 0 3px rgba(9,105,218,0.1); }
        .header { background: #24292f; color: white; padding: 1rem 0; margin-bottom: 2rem; box-shadow: 0 1px 3px rgba(0,0,0,0.12); }
        .header-content { max-width: 1280px; margin: 0 auto; padding: 0 2rem; display: flex; justify-content: space-between; align-items: center; }
        .logo { font-size: 1.5rem; font-weight: 700; display: flex; align-items: center; gap: 0.5rem; }
        .tab-nav { display: flex; gap: 0.5rem; margin-bottom: 1rem; border-bottom: 1px solid #d0d7de; }
        .tab { padding: 0.75rem 1rem; cursor: pointer; border-bottom: 2px solid transparent; transition: all 0.2s; font-weight: 500; color: #57606a; }
        .tab.active { color: #24292f; border-bottom-color: #fd8c73; }
        .tab:hover { color: #24292f; }
        .message-list { display: flex; flex-direction: column; gap: 0.5rem; }
        .message-item { padding: 1rem; border: 1px solid #d0d7de; border-radius: 6px; cursor: pointer; transition: all 0.2s; background: white; }
        .message-item:hover { border-color: #0969da; background: #f6f8fa; }
        .modal-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; z-index: 1000; }
        .modal { background: white; border-radius: 6px; padding: 1.5rem; max-width: 600px; width: 90%; max-height: 90vh; overflow-y: auto; box-shadow: 0 8px 24px rgba(0,0,0,0.2); }
        .modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; padding-bottom: 0.75rem; border-bottom: 1px solid #d0d7de; }
        .modal-title { font-size: 1.25rem; font-weight: 600; }
        .close-btn { background: none; border: none; font-size: 1.5rem; cursor: pointer; color: #57606a; padding: 0; width: 2rem; height: 2rem; display: flex; align-items: center; justify-content: center; border-radius: 6px; }
        .close-btn:hover { background: #f6f8fa; color: #24292f; }
        .notification { position: fixed; top: 1rem; right: 1rem; background: white; border: 1px solid #d0d7de; border-radius: 6px; padding: 1rem 1.5rem; box-shadow: 0 8px 24px rgba(0,0,0,0.15); z-index: 2000; min-width: 300px; animation: slideIn 0.3s ease-out; }
        .notification.success { border-left: 4px solid #2da44e; }
        .notification.error { border-left: 4px solid #cf222e; }
        .notification.info { border-left: 4px solid #0969da; }
        @keyframes slideIn { from { transform: translateX(400px); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
        .label { display: block; font-weight: 600; margin-bottom: 0.5rem; font-size: 14px; color: #24292f; }
        .form-group { margin-bottom: 1rem; }
        .textarea { width: 100%; padding: 0.5rem 0.75rem; border: 1px solid #d0d7de; border-radius: 6px; font-size: 14px; font-family: inherit; resize: vertical; min-height: 100px; }
        .textarea:focus { outline: none; border-color: #0969da; box-shadow: 0 0 0 3px rgba(9,105,218,0.1); }
        .attachment-list { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 0.5rem; }
        .attachment-item { display: flex; align-items: center; gap: 0.5rem; padding: 0.5rem 0.75rem; background: #f6f8fa; border: 1px solid #d0d7de; border-radius: 6px; font-size: 12px; }
        .attachment-item button { background: none; border: none; color: #cf222e; cursor: pointer; font-size: 1rem; padding: 0; width: 1.25rem; height: 1.25rem; display: flex; align-items: center; justify-content: center; border-radius: 3px; }
        .attachment-item button:hover { background: #ffebe9; }
        .empty-state { text-align: center; padding: 3rem 1rem; color: #57606a; }
        .empty-state-icon { font-size: 3rem; margin-bottom: 1rem; opacity: 0.5; }
        .hidden { display: none !important; }
        .flex { display: flex; }
        .gap-2 { gap: 0.5rem; }
        .items-center { align-items: center; }
        .justify-between { justify-content: space-between; }
        .text-sm { font-size: 14px; }
        .text-xs { font-size: 12px; }
        .text-gray { color: #57606a; }
        .font-semibold { font-weight: 600; }
        .w-full { width: 100%; }
        .hint { font-size: 12px; color: #57606a; margin-top: 0.25rem; }
        .text-center { text-align: center; }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <div class="logo"><span style="font-size: 1.75rem;">🔒</span> xsukax E2EE Local Mailing System</div>
            <div id="userInfo" class="hidden text-sm"></div>
        </div>
    </div>

    <div class="container">
        <!-- Auth View -->
        <div id="authView" class="card">
            <div class="text-center mb-4">
                <span class="text-sm text-gray">Connected to: <strong><?php echo DOMAIN; ?></strong></span>
            </div>
            <h2 class="text-xl font-semibold mb-4">Authentication</h2>
            <div class="flex gap-2 mb-4">
                <button onclick="showRegister()" id="registerTab" class="btn btn-primary flex-1">Register</button>
                <button onclick="showLogin()" id="loginTab" class="btn btn-secondary flex-1">Login</button>
            </div>

            <!-- Register Form -->
            <div id="registerForm">
                <div class="form-group">
                    <label class="label">Username</label>
                    <div class="flex gap-2 items-center">
                        <input type="text" id="regUsername" class="input flex-1" placeholder="username">
                        <span class="text-gray">@<?php echo DOMAIN; ?></span>
                    </div>
                    <p class="hint">Choose a unique username (3-30 characters, alphanumeric only)</p>
                </div>
                <div class="form-group">
                    <label class="label">Password</label>
                    <input type="password" id="regPassword" class="input" placeholder="Enter a strong password">
                    <p class="hint">Minimum 6 characters</p>
                </div>
                <button onclick="register()" class="btn btn-primary w-full">Create Account</button>
            </div>

            <!-- Login Form -->
            <div id="loginForm" class="hidden">
                <div class="form-group">
                    <label class="label">Username</label>
                    <div class="flex gap-2 items-center">
                        <input type="text" id="loginUsername" class="input flex-1" placeholder="username">
                        <span class="text-gray">@<?php echo DOMAIN; ?></span>
                    </div>
                </div>
                <div class="form-group">
                    <label class="label">Password</label>
                    <input type="password" id="loginPassword" class="input" placeholder="Enter your password">
                </div>
                <button onclick="login()" class="btn btn-primary w-full">Login</button>
            </div>
        </div>

        <!-- Mail View -->
        <div id="mailView" class="hidden">
            <div class="card">
                <div class="flex justify-between items-center mb-4">
                    <h2 class="text-xl font-semibold">📬 Mailbox</h2>
                    <button onclick="logout()" class="btn btn-secondary">Logout</button>
                </div>

                <div class="tab-nav">
                    <div class="tab active" onclick="switchTab('inbox')">📥 Inbox</div>
                    <div class="tab" onclick="switchTab('sent')">📤 Sent</div>
                    <div class="tab" onclick="switchTab('trash')">🗑️ Trash</div>
                    <div class="tab" onclick="switchTab('compose')">✉️ Compose</div>
                </div>

                <!-- Inbox Tab -->
                <div id="inboxTab" class="tab-content">
                    <div class="flex justify-between items-center mb-4">
                        <h3 class="font-semibold">Inbox</h3>
                        <button onclick="loadMessages('inbox')" class="btn btn-secondary">🔄 Refresh</button>
                    </div>
                    <div id="inboxMessages" class="message-list"></div>
                </div>

                <!-- Sent Tab -->
                <div id="sentTab" class="tab-content hidden">
                    <div class="flex justify-between items-center mb-4">
                        <h3 class="font-semibold">Sent Messages</h3>
                        <button onclick="loadMessages('sent')" class="btn btn-secondary">🔄 Refresh</button>
                    </div>
                    <div id="sentMessages" class="message-list"></div>
                </div>

                <!-- Trash Tab -->
                <div id="trashTab" class="tab-content hidden">
                    <div class="flex justify-between items-center mb-4">
                        <h3 class="font-semibold">Trash</h3>
                        <button onclick="loadMessages('trash')" class="btn btn-secondary">🔄 Refresh</button>
                    </div>
                    <div id="trashMessages" class="message-list"></div>
                </div>

                <!-- Compose Tab -->
                <div id="composeTab" class="tab-content hidden">
                    <h3 class="font-semibold mb-4">Compose New Message</h3>
                    <div class="form-group">
                        <label class="label">Send To</label>
                        <div class="flex gap-2 items-center">
                            <input type="text" id="composeTo" class="input flex-1" placeholder="recipient username">
                            <span class="text-gray">@<?php echo DOMAIN; ?></span>
                        </div>
                    </div>
                    <div class="form-group">
                        <label class="label">Subject</label>
                        <input type="text" id="composeSubject" class="input" placeholder="Message subject">
                    </div>
                    <div class="form-group">
                        <label class="label">Encryption Key (Password) 🔐</label>
                        <input type="password" id="composeKey" class="input" placeholder="Enter encryption password">
                        <p class="hint">Share this password securely with the recipient</p>
                    </div>
                    <div class="form-group">
                        <label class="label">Message</label>
                        <textarea id="composeContent" class="textarea" placeholder="Type your encrypted message..."></textarea>
                    </div>
                    <div class="form-group">
                        <label class="label">Attachments (Optional) 📎</label>
                        <input type="file" id="composeAttachments" class="input" multiple onchange="handleAttachmentSelect(event)">
                        <div id="attachmentList" class="attachment-list"></div>
                    </div>
                    <button onclick="sendMessage()" class="btn btn-primary">🔒 Send Encrypted Message</button>
                </div>
            </div>
        </div>
    </div>

    <script>
        const API_URL = '<?php echo $currentUrl; ?>';
        const DOMAIN = '<?php echo DOMAIN; ?>';
        let AUTH_TOKEN = '';
        let CURRENT_USER = null;
        let selectedAttachments = [];

        function showNotification(message, type = 'info') {
            const notification = document.createElement('div');
            notification.className = `notification ${type}`;
            notification.textContent = message;
            document.body.appendChild(notification);
            setTimeout(() => notification.remove(), 4000);
        }

        function showModal(title, content) {
            const overlay = document.createElement('div');
            overlay.className = 'modal-overlay';
            overlay.innerHTML = `
                <div class="modal">
                    <div class="modal-header">
                        <h3 class="modal-title">${title}</h3>
                        <button class="close-btn" onclick="closeModal(this)">×</button>
                    </div>
                    <div>${content}</div>
                </div>
            `;
            overlay.onclick = (e) => { if (e.target === overlay) closeModal(overlay.querySelector('.close-btn')); };
            document.body.appendChild(overlay);
        }

        function closeModal(btn) {
            btn.closest('.modal-overlay').remove();
        }

        function showRegister() {
            document.getElementById('registerTab').classList.remove('btn-secondary');
            document.getElementById('registerTab').classList.add('btn-primary');
            document.getElementById('loginTab').classList.remove('btn-primary');
            document.getElementById('loginTab').classList.add('btn-secondary');
            document.getElementById('registerForm').classList.remove('hidden');
            document.getElementById('loginForm').classList.add('hidden');
        }

        function showLogin() {
            document.getElementById('loginTab').classList.remove('btn-secondary');
            document.getElementById('loginTab').classList.add('btn-primary');
            document.getElementById('registerTab').classList.remove('btn-primary');
            document.getElementById('registerTab').classList.add('btn-secondary');
            document.getElementById('loginForm').classList.remove('hidden');
            document.getElementById('registerForm').classList.add('hidden');
        }

        async function deriveKey(password, salt) {
            const encoder = new TextEncoder();
            const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
            return crypto.subtle.deriveKey(
                { name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' },
                keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
            );
        }

        async function encryptData(data, password) {
            const encoder = new TextEncoder();
            const salt = crypto.getRandomValues(new Uint8Array(16));
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const key = await deriveKey(password, salt);
            const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, encoder.encode(data));
            const result = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
            result.set(salt, 0);
            result.set(iv, salt.length);
            result.set(new Uint8Array(encrypted), salt.length + iv.length);
            return btoa(String.fromCharCode(...result));
        }

        async function decryptData(encryptedData, password) {
            try {
                const data = Uint8Array.from(atob(encryptedData), c => c.charCodeAt(0));
                const salt = data.slice(0, 16);
                const iv = data.slice(16, 28);
                const encrypted = data.slice(28);
                const key = await deriveKey(password, salt);
                const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, encrypted);
                return new TextDecoder().decode(decrypted);
            } catch (error) {
                throw new Error('Decryption failed - wrong password');
            }
        }

        async function register() {
            const username = document.getElementById('regUsername').value.trim();
            const password = document.getElementById('regPassword').value;
            if (!username || !password) {
                showNotification('Please fill all fields', 'error');
                return;
            }
            try {
                const response = await fetch(`${API_URL}?api=1&action=register`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                const data = await response.json();
                if (data.success) {
                    showNotification('✅ Registration successful! Please login.', 'success');
                    showLogin();
                    document.getElementById('loginUsername').value = username;
                } else {
                    showNotification(data.message || 'Registration failed', 'error');
                }
            } catch (error) {
                showNotification('Registration failed: ' + error.message, 'error');
            }
        }

        async function login() {
            const username = document.getElementById('loginUsername').value.trim();
            const password = document.getElementById('loginPassword').value;
            if (!username || !password) {
                showNotification('Please fill all fields', 'error');
                return;
            }
            const email = `${username}@${DOMAIN}`;
            try {
                const response = await fetch(`${API_URL}?api=1&action=login`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password })
                });
                const data = await response.json();
                if (data.success) {
                    AUTH_TOKEN = data.token;
                    CURRENT_USER = data.user;
                    document.getElementById('authView').classList.add('hidden');
                    document.getElementById('mailView').classList.remove('hidden');
                    document.getElementById('userInfo').classList.remove('hidden');
                    document.getElementById('userInfo').textContent = `Logged in as ${CURRENT_USER.email}`;
                    showNotification('✅ Login successful!', 'success');
                    loadMessages('inbox');
                } else {
                    showNotification(data.message || 'Login failed', 'error');
                }
            } catch (error) {
                showNotification('Login failed: ' + error.message, 'error');
            }
        }

        function logout() {
            AUTH_TOKEN = '';
            CURRENT_USER = null;
            document.getElementById('mailView').classList.add('hidden');
            document.getElementById('authView').classList.remove('hidden');
            document.getElementById('userInfo').classList.add('hidden');
            showNotification('Logged out successfully', 'success');
        }

        function switchTab(tab) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.add('hidden'));
            event.target.classList.add('active');
            document.getElementById(`${tab}Tab`).classList.remove('hidden');
            if (tab === 'inbox' || tab === 'sent' || tab === 'trash') loadMessages(tab);
        }

        function handleAttachmentSelect(event) {
            selectedAttachments = Array.from(event.target.files);
            displayAttachments();
        }

        function displayAttachments() {
            const list = document.getElementById('attachmentList');
            list.innerHTML = selectedAttachments.map((file, index) => `
                <div class="attachment-item">
                    <span>📎 ${file.name} (${(file.size / 1024).toFixed(2)} KB)</span>
                    <button onclick="removeAttachment(${index})">×</button>
                </div>
            `).join('');
        }

        function removeAttachment(index) {
            selectedAttachments.splice(index, 1);
            displayAttachments();
        }

        async function sendMessage() {
            const toUsername = document.getElementById('composeTo').value.trim();
            const subject = document.getElementById('composeSubject').value.trim();
            const key = document.getElementById('composeKey').value;
            const content = document.getElementById('composeContent').value;
            if (!toUsername || !subject || !key || !content) {
                showNotification('Please fill all required fields', 'error');
                return;
            }
            const to = `${toUsername}@${DOMAIN}`;
            try {
                const encryptedContent = await encryptData(content, key);
                let encryptedAttachments = [];
                for (const file of selectedAttachments) {
                    const reader = new FileReader();
                    const fileData = await new Promise((resolve) => {
                        reader.onload = (e) => resolve(e.target.result);
                        reader.readAsDataURL(file);
                    });
                    const encryptedFile = await encryptData(fileData, key);
                    encryptedAttachments.push({ filename: file.name, data: encryptedFile });
                }
                const response = await fetch(`${API_URL}?api=1&action=send`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
                    body: JSON.stringify({ to, subject, encrypted_content: encryptedContent, encrypted_attachments: encryptedAttachments })
                });
                const data = await response.json();
                if (data.success) {
                    showNotification('✅ Message sent successfully!', 'success');
                    document.getElementById('composeTo').value = '';
                    document.getElementById('composeSubject').value = '';
                    document.getElementById('composeKey').value = '';
                    document.getElementById('composeContent').value = '';
                    document.getElementById('composeAttachments').value = '';
                    selectedAttachments = [];
                    displayAttachments();
                } else {
                    showNotification(data.message || 'Failed to send message', 'error');
                }
            } catch (error) {
                showNotification('Failed to send message: ' + error.message, 'error');
            }
        }

        async function loadMessages(type) {
            try {
                const response = await fetch(`${API_URL}?api=1&action=messages&type=${type}`, {
                    headers: { 'Authorization': `Bearer ${AUTH_TOKEN}` }
                });
                const data = await response.json();
                if (data.success) displayMessages(data.messages, type);
                else showNotification('Failed to load messages', 'error');
            } catch (error) {
                showNotification('Failed to load messages: ' + error.message, 'error');
            }
        }

        function displayMessages(messages, type) {
            const container = document.getElementById(`${type}Messages`);
            if (!messages || messages.length === 0) {
                container.innerHTML = `<div class="empty-state"><div class="empty-state-icon">📭</div><p>No messages in ${type}</p></div>`;
                return;
            }
            
            container.innerHTML = messages.map(msg => {
                const displayUser = type === 'sent' ? `To: ${msg.to_user}` : `From: ${msg.from_user}`;
                return `
                    <div class="message-item" onclick="viewMessage(${msg.id}, '${type}')">
                        <div class="flex justify-between items-center mb-2">
                            <span class="font-semibold">${displayUser}</span>
                            <span class="text-xs text-gray">${new Date(msg.created_at).toLocaleString()}</span>
                        </div>
                        <div class="font-semibold text-sm mb-1">📧 ${msg.subject}</div>
                        <div class="text-xs text-gray">🔒 Encrypted - Click to decrypt</div>
                        ${msg.attachments_count > 0 ? `<div class="text-xs text-gray mt-1">📎 ${msg.attachments_count} attachment(s)</div>` : ''}
                    </div>
                `;
            }).join('');
        }

        async function viewMessage(id, type) {
            try {
                const response = await fetch(`${API_URL}?api=1&action=message&id=${id}`, {
                    headers: { 'Authorization': `Bearer ${AUTH_TOKEN}` }
                });
                const data = await response.json();
                if (data.success) showDecryptModal(data.message, type);
            } catch (error) {
                showNotification('Failed to load message: ' + error.message, 'error');
            }
        }

        function showDecryptModal(message, type) {
            const content = `
                <div class="form-group">
                    <label class="label">🔐 Enter decryption key</label>
                    <input type="password" id="decryptKey" class="input" placeholder="Enter encryption password">
                </div>
                <div class="flex gap-2">
                    <button onclick="decryptMessage(${message.id}, '${type}')" class="btn btn-primary">🔓 Decrypt</button>
                    ${type === 'inbox' ? `<button onclick="moveToTrash(${message.id})" class="btn btn-danger">🗑️ Trash</button>` : ''}
                    ${type === 'trash' ? `<button onclick="permanentDelete(${message.id})" class="btn btn-danger">⚠️ Delete</button>` : ''}
                </div>
            `;
            showModal(`📨 ${message.from_user} - ${message.subject}`, content);
        }

        async function decryptMessage(id, type) {
            const key = document.getElementById('decryptKey').value;
            if (!key) {
                showNotification('Please enter decryption key', 'error');
                return;
            }
            try {
                const response = await fetch(`${API_URL}?api=1&action=message&id=${id}`, {
                    headers: { 'Authorization': `Bearer ${AUTH_TOKEN}` }
                });
                const data = await response.json();
                if (data.success) {
                    const decryptedContent = await decryptData(data.message.encrypted_content, key);
                    let attachmentsHtml = '';
                    if (data.message.encrypted_attachments) {
                        const attachments = JSON.parse(data.message.encrypted_attachments);
                        attachmentsHtml = '<div class="mt-4"><strong>📎 Attachments:</strong><div class="attachment-list mt-2">';
                        for (const att of attachments) {
                            const decryptedData = await decryptData(att.data, key);
                            attachmentsHtml += `<div class="attachment-item"><a href="${decryptedData}" download="${att.filename}">💾 ${att.filename}</a></div>`;
                        }
                        attachmentsHtml += '</div></div>';
                    }
                    const content = `
                        <div class="mb-4">
                            <strong>From:</strong> ${data.message.from_user}<br>
                            <strong>To:</strong> ${data.message.to_user}<br>
                            <strong>Subject:</strong> ${data.message.subject}<br>
                            <strong>Date:</strong> ${new Date(data.message.created_at).toLocaleString()}
                        </div>
                        <div class="card"><div style="white-space: pre-wrap;">${decryptedContent}</div></div>
                        ${attachmentsHtml}
                        <div class="flex gap-2 mt-4">
                            ${type === 'inbox' ? `<button onclick="moveToTrash(${id})" class="btn btn-danger">🗑️ Trash</button>` : ''}
                            ${type === 'trash' ? `<button onclick="permanentDelete(${id})" class="btn btn-danger">⚠️ Delete</button>` : ''}
                        </div>
                    `;
                    closeModal(document.querySelector('.close-btn'));
                    showModal(`✉️ Message`, content);
                }
            } catch (error) {
                showNotification(error.message || 'Decryption failed', 'error');
            }
        }

        async function moveToTrash(id) {
            try {
                const response = await fetch(`${API_URL}?api=1&action=trash&id=${id}`, {
                    method: 'POST',
                    headers: { 'Authorization': `Bearer ${AUTH_TOKEN}` }
                });
                const data = await response.json();
                if (data.success) {
                    showNotification('Message moved to trash', 'success');
                    closeModal(document.querySelector('.close-btn'));
                    loadMessages('inbox');
                }
            } catch (error) {
                showNotification('Failed to move message: ' + error.message, 'error');
            }
        }

        async function permanentDelete(id) {
            try {
                const response = await fetch(`${API_URL}?api=1&action=delete&id=${id}`, {
                    method: 'DELETE',
                    headers: { 'Authorization': `Bearer ${AUTH_TOKEN}` }
                });
                const data = await response.json();
                if (data.success) {
                    showNotification('Message deleted permanently', 'success');
                    closeModal(document.querySelector('.close-btn'));
                    loadMessages('trash');
                }
            } catch (error) {
                showNotification('Failed to delete message: ' + error.message, 'error');
            }
        }
    </script>
</body>
</html>
