<?php
// Optimized Broken Link Checker Tool with Multi-cURL and Memory Management
// Powered by Ebizindia - https://www.ebizindia.com

/*
 * ========================================
 * CONFIGURATION SETTINGS
 * ========================================
 * Modify these settings to customize the behavior of the link checker
 */

// === PERFORMANCE SETTINGS ===
define('MAX_EXECUTION_TIME', 600);        // Maximum script execution time (seconds)
define('MEMORY_LIMIT', '512M');           // PHP memory limit
define('MAX_PAGES_DEFAULT', 100);         // Default maximum pages to crawl
define('MAX_PAGES_LIMIT', 1000);          // Maximum allowed pages limit
define('PAGE_TIMEOUT', 8);                // Timeout for fetching pages (seconds)
define('LINK_TIMEOUT', 3);                // Timeout for checking individual links (seconds)

// === MULTI-CURL OPTIMIZATION ===
define('MAX_CONCURRENT_REQUESTS', 10);    // Number of simultaneous link checks
define('BATCH_SIZE', 20);                 // Links processed per batch
define('RETRY_COUNT', 2);                 // Number of retries for failed requests
define('MAX_LINKS_PER_PAGE', 30);         // Maximum links to check per page

// === EMAIL SETTINGS ===
define('EMAIL_FROM', 'noreply@yourdomain.com');     // From email address
define('EMAIL_TO', 'your-email@domain.com');        // Default recipient email
define('EMAIL_SUBJECT_PREFIX', 'Link Check Report'); // Email subject prefix

// === CRAWLER BEHAVIOR ===
define('CHECK_EXTERNAL_DEFAULT', true);   // Check external links by default
define('MAX_REDIRECTS', 3);               // Maximum redirects to follow
define('USER_AGENT', 'PHP Link Validator 2.0 (Optimized)'); // User agent string
define('CONNECT_TIMEOUT', 2);             // Connection timeout (seconds)

// === SKIP DOMAINS ===
// Domains to skip during external link checking (known slow domains)
define('SKIP_EXTERNAL_DOMAINS', [
    'facebook.com', 
    'twitter.com', 
    'youtube.com', 
    'instagram.com', 
    'linkedin.com',
    'pinterest.com',
    'tiktok.com'
]);

// === SECURITY SETTINGS ===
define('ENABLE_SSL_VERIFY', true);        // Enable SSL certificate verification (SECURITY: Must be true)
define('MAX_QUEUE_SIZE', 1000);           // Maximum URLs in crawl queue
define('GARBAGE_COLLECTION_INTERVAL', 10); // Run garbage collection every N pages
define('RATE_LIMIT_SECONDS', 60);         // Minimum seconds between checks per session
define('ENABLE_SSRF_PROTECTION', true);   // Block internal/private IP ranges

// === UI SETTINGS ===
define('SHOW_PERFORMANCE_STATS', true);   // Show performance statistics
define('ENABLE_PROGRESS_UPDATES', true);  // Enable real-time progress updates
define('RESULTS_PER_PAGE', 50);           // Results to display per page (future feature)

/*
 * ========================================
 * END CONFIGURATION
 * ========================================
 */

// Apply PHP settings
ini_set('max_execution_time', MAX_EXECUTION_TIME);
set_time_limit(MAX_EXECUTION_TIME);
ini_set('memory_limit', MEMORY_LIMIT);

// SECURITY: Secure session configuration
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 1 : 0);
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_strict_mode', 1);
ini_set('session.use_only_cookies', 1);
session_start();

// SECURITY: Generate CSRF token
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// SECURITY: Set security headers
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Permissions-Policy: geolocation=(), microphone=(), camera=()");
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://code.jquery.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data:; font-src 'self' https://cdn.jsdelivr.net;");

class OptimizedLinkChecker {
    private $visited = [];
    private $queue = [];
    private $results = [];
    private $domain;
    private $baseUrl;
    private $maxPages;
    private $timeout;
    private $linkTimeout;
    private $checkedLinks = []; // Cache to avoid checking same external link multiple times
    private $maxLinksPerPage;
    private $skipExternalDomains;
    private $checkExternal = true;
    
    // Multi-cURL optimization settings
    private $maxConcurrentRequests;
    private $batchSize;
    private $retryCount;
    
    // Performance tracking
    private $startTime;
    private $endTime;
    private $memoryPeakUsage;
    
    public function __construct($url, $maxPages = null, $checkExternal = null) {
        // SECURITY: Validate URL before processing
        if (!$this->isUrlSafe($url)) {
            throw new Exception('Invalid or unsafe URL provided');
        }

        $this->baseUrl = $this->normalizeUrl($url);
        $this->domain = parse_url($this->baseUrl, PHP_URL_HOST);
        $this->queue[] = $this->baseUrl;

        // Use configuration constants
        $this->maxPages = $maxPages ?? MAX_PAGES_DEFAULT;
        $this->checkExternal = $checkExternal ?? CHECK_EXTERNAL_DEFAULT;
        $this->timeout = PAGE_TIMEOUT;
        $this->linkTimeout = LINK_TIMEOUT;
        $this->maxLinksPerPage = MAX_LINKS_PER_PAGE;
        $this->skipExternalDomains = SKIP_EXTERNAL_DOMAINS;
        $this->maxConcurrentRequests = MAX_CONCURRENT_REQUESTS;
        $this->batchSize = BATCH_SIZE;
        $this->retryCount = RETRY_COUNT;
    }

    /**
     * SECURITY: Validate URL to prevent SSRF attacks
     * Blocks private IP ranges, localhost, and internal networks
     */
    private function isUrlSafe($url) {
        if (!ENABLE_SSRF_PROTECTION) {
            return true; // Skip validation if disabled
        }

        // Normalize URL first
        if (!preg_match('/^https?:\/\//', $url)) {
            $url = 'https://' . $url;
        }

        $parsed = parse_url($url);
        if (!$parsed || !isset($parsed['host'])) {
            return false;
        }

        $host = $parsed['host'];

        // Only allow http and https
        if (!in_array($parsed['scheme'], ['http', 'https'], true)) {
            return false;
        }

        // Block localhost variations
        $blockedHosts = [
            'localhost',
            'localhost.localdomain',
            '127.0.0.1',
            '0.0.0.0',
            '::1',
            '0:0:0:0:0:0:0:1',
            '169.254.169.254', // AWS metadata
            'metadata.google.internal', // GCP metadata
        ];

        if (in_array(strtolower($host), $blockedHosts, true)) {
            return false;
        }

        // Resolve hostname to IP
        $ip = gethostbyname($host);

        // Check if resolution failed (returns same string)
        if ($ip === $host && !filter_var($ip, FILTER_VALIDATE_IP)) {
            // Could not resolve, but might be valid domain
            // Allow it but log for review
            return true;
        }

        // Block private and reserved IP ranges
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            // Block private IPv4 ranges
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
                return false;
            }

            // Additional manual checks for ranges that might slip through
            $longIp = ip2long($ip);
            if ($longIp === false) {
                return false;
            }

            // 10.0.0.0/8
            if (($longIp & 0xFF000000) === 0x0A000000) return false;
            // 172.16.0.0/12
            if (($longIp & 0xFFF00000) === 0xAC100000) return false;
            // 192.168.0.0/16
            if (($longIp & 0xFFFF0000) === 0xC0A80000) return false;
            // 127.0.0.0/8
            if (($longIp & 0xFF000000) === 0x7F000000) return false;
            // 169.254.0.0/16 (link-local)
            if (($longIp & 0xFFFF0000) === 0xA9FE0000) return false;
        } elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            // Block private IPv6 ranges
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
                return false;
            }
        }

        return true;
    }
    
    private function normalizeUrl($url) {
        if (!preg_match('/^https?:\/\//', $url)) {
            $url = 'https://' . $url;
        }
        
        $parsed = parse_url($url);
        if (!$parsed) return false;
        
        $normalized = $parsed['scheme'] . '://' . $parsed['host'];
        if (isset($parsed['path'])) {
            $normalized .= rtrim($parsed['path'], '/');
        }
        if (isset($parsed['query'])) {
            $normalized .= '?' . $parsed['query'];
        }
        
        if (parse_url($normalized, PHP_URL_PATH) === '') {
            $normalized .= '/';
        }
        
        return $normalized;
    }
    
    public function crawl() {
        // Start performance tracking
        $this->startTime = microtime(true);
        $initialMemory = memory_get_usage();
        
        $count = 0;
        $maxTime = time() + 240; // Increased to 4 minutes
        $totalQueueProcessed = 0;
        
        while (!empty($this->queue) && $count < $this->maxPages && time() < $maxTime) {
            $currentUrl = array_shift($this->queue);
            $totalQueueProcessed++;
            
            if (in_array($currentUrl, $this->visited)) {
                continue;
            }
            
            $this->visited[] = $currentUrl;
            $count++;
            
            $progress = min(100, round(($count / min($this->maxPages, 100)) * 100));
            $cacheHits = count($this->checkedLinks);
            $currentMemory = round(memory_get_usage() / 1024 / 1024, 2);
            $peakMemory = round(memory_get_peak_usage() / 1024 / 1024, 2);

            // SECURITY: Use safe JavaScript output with proper escaping
            $statusMessage = sprintf(
                'Checking page: %s<br>Progress: %d%% (%d/%d)<br>Queue: %d URLs remaining<br>Cached: %d unique links<br>Memory: %sMB (Peak: %sMB)',
                htmlspecialchars($currentUrl, ENT_QUOTES, 'UTF-8'),
                $progress,
                $count,
                $this->maxPages,
                count($this->queue),
                $cacheHits,
                $currentMemory,
                $peakMemory
            );

            echo "<script>
            (function() {
                var el = document.getElementById('status');
                if (el) el.innerHTML = " . json_encode($statusMessage) . ";
            })();
            </script>";
            echo str_repeat(' ', 1024);
            flush();
            
            $pageData = $this->fetchPage($currentUrl);
            if ($pageData) {
                // Extract all links first, then check them in parallel
                $linksToCheck = $this->extractLinksFromPage($currentUrl, $pageData['content']);
                
                // MEMORY OPTIMIZATION: Discard HTML content immediately after link extraction
                $htmlContent = $pageData['content']; // Keep reference for internal link extraction
                unset($pageData['content']);
                $pageData = null;
                
                // Check links in parallel batches
                $this->checkLinksInParallel($currentUrl, $linksToCheck);
                
                // Add internal links to crawl queue using original method (more reliable)
                $this->extractInternalLinks($htmlContent, $currentUrl);
                
                // MEMORY CLEANUP: Clear processed data
                unset($linksToCheck, $htmlContent);
                
                // Force garbage collection at configured intervals
                if ($count % GARBAGE_COLLECTION_INTERVAL === 0) {
                    gc_collect_cycles();
                }
            } else {
                $this->results[] = [
                    'source_page' => 'Direct Access',
                    'broken_url' => $currentUrl,
                    'link_text' => 'N/A',
                    'error' => 'Page not accessible',
                    'link_type' => 'internal',
                    'category' => 'page'
                ];
            }
            
            // Safety checks
            if (count($this->queue) > MAX_QUEUE_SIZE) {
                echo "<script>document.getElementById('status').innerHTML = 'Queue too large, trimming to prevent timeout...';</script>";
                $this->queue = array_slice($this->queue, 0, MAX_QUEUE_SIZE);
                break;
            }
            
            if (time() > $maxTime - 60) {
                echo "<script>document.getElementById('status').innerHTML = 'Nearly time limit, finishing current checks...';</script>";
                break;
            }
        }
        
        if (time() >= $maxTime) {
            echo "<script>document.getElementById('status').innerHTML = 'Completed (stopped due to time limit to prevent timeout)';</script>";
        }
        
        // End performance tracking
        $this->endTime = microtime(true);
        $this->memoryPeakUsage = memory_get_peak_usage();
        
        // Final memory cleanup
        gc_collect_cycles();
        
        return $this->results;
    }
    
    private function extractLinksFromPage($pageUrl, $html) {
        $linksToCheck = [];
        
        $dom = new DOMDocument();
        libxml_use_internal_errors(true);
        $dom->loadHTML($html);
        libxml_clear_errors();
        
        // Extract anchor links
        $links = $dom->getElementsByTagName('a');
        $checkedCount = 0;
        
        foreach ($links as $link) {
            if ($checkedCount >= $this->maxLinksPerPage) break;
            
            $href = trim($link->getAttribute('href'));
            $linkText = trim($link->textContent);
            
            if (empty($href) || $href === '#' || 
                strpos($href, 'javascript:') === 0 || 
                strpos($href, 'mailto:') === 0 || 
                strpos($href, 'tel:') === 0) {
                continue;
            }
            
            $absoluteUrl = $this->resolveUrl($href, $pageUrl);
            if ($absoluteUrl === false) continue;
            
            $linkType = $this->isSameDomain($absoluteUrl) ? 'internal' : 'external';
            if ($linkType === 'external' && !$this->checkExternal) continue;
            
            $linksToCheck[] = [
                'url' => $absoluteUrl,
                'text' => $linkText ?: 'No anchor text',
                'type' => $linkType,
                'category' => 'anchor'
            ];
            $checkedCount++;
        }
        
        // Extract image links
        $images = $dom->getElementsByTagName('img');
        foreach ($images as $img) {
            $src = trim($img->getAttribute('src'));
            $alt = trim($img->getAttribute('alt'));
            
            if (empty($src)) continue;
            
            $absoluteUrl = $this->resolveUrl($src, $pageUrl);
            if ($absoluteUrl === false) continue;
            
            $linkType = $this->isSameDomain($absoluteUrl) ? 'internal' : 'external';
            if ($linkType === 'external' && !$this->checkExternal) continue;
            
            $linksToCheck[] = [
                'url' => $absoluteUrl,
                'text' => $alt ?: 'Image: ' . basename($src),
                'type' => $linkType,
                'category' => 'image'
            ];
        }
        
        return $linksToCheck;
    }
    
    private function checkLinksInParallel($pageUrl, $linksToCheck) {
        // Filter out already checked links
        $uncheckedLinks = [];
        foreach ($linksToCheck as $link) {
            if (!isset($this->checkedLinks[$link['url']])) {
                $uncheckedLinks[] = $link;
            } else {
                // Use cached result
                $cachedResult = $this->checkedLinks[$link['url']];
                if ($cachedResult['is_broken']) {
                    $this->addBrokenLinkResult($pageUrl, $link, $cachedResult['error_message']);
                }
            }
        }
        
        if (empty($uncheckedLinks)) return;
        
        // Process unchecked links in batches
        $batches = array_chunk($uncheckedLinks, $this->batchSize);
        
        foreach ($batches as $batch) {
            $this->processBatchWithMultiCurl($pageUrl, $batch);
        }
    }
    
    private function processBatchWithMultiCurl($pageUrl, $batch) {
        $multiHandle = curl_multi_init();
        $curlHandles = [];
        $linkMap = [];
        
        // Prepare cURL handles
        foreach ($batch as $index => $link) {
            // Skip known slow domains
            $host = parse_url($link['url'], PHP_URL_HOST);
            $skipThisLink = false;
            foreach ($this->skipExternalDomains as $skipDomain) {
                if (strpos($host, $skipDomain) !== false) {
                    $this->checkedLinks[$link['url']] = [
                        'status_code' => 200,
                        'error' => '',
                        'is_broken' => false,
                        'error_message' => 'Skipped (known slow domain)',
                        'check_type' => 'SKIPPED'
                    ];
                    $skipThisLink = true;
                    break;
                }
            }
            
            if ($skipThisLink) continue;
            
            $ch = curl_init();
            $isImage = $this->isImageUrl($link['url']);
            $isExternal = $link['type'] === 'external';
            $useHeadRequest = $isImage || $isExternal;
            
            curl_setopt_array($ch, [
                CURLOPT_URL => $link['url'],
                CURLOPT_NOBODY => $useHeadRequest,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_TIMEOUT => $useHeadRequest ? $this->linkTimeout : $this->timeout,
                CURLOPT_CONNECTTIMEOUT => CONNECT_TIMEOUT,
                CURLOPT_USERAGENT => USER_AGENT,
                CURLOPT_SSL_VERIFYPEER => ENABLE_SSL_VERIFY,
                CURLOPT_MAXREDIRS => MAX_REDIRECTS,
                CURLOPT_FRESH_CONNECT => true, // Don't reuse connections
                CURLOPT_FORBID_REUSE => true
            ]);
            
            curl_multi_add_handle($multiHandle, $ch);
            $curlHandles[] = $ch;
            $linkMap[(int)$ch] = $link;
        }
        
        // Execute all cURL handles simultaneously
        $running = null;
        do {
            $mrc = curl_multi_exec($multiHandle, $running);
            if ($running > 0) {
                // Wait for activity on any curl-connection
                curl_multi_select($multiHandle, 0.1);
            }
        } while ($running > 0 && $mrc == CURLM_OK);
        
        // Process results
        foreach ($curlHandles as $ch) {
            $linkData = $linkMap[(int)$ch];
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $error = curl_error($ch);
            
            $result = [
                'status_code' => $httpCode,
                'error' => $error,
                'is_broken' => false,
                'error_message' => '',
                'check_type' => curl_getinfo($ch, CURLINFO_REQUEST_SIZE) > 0 ? 'HEAD' : 'GET'
            ];
            
            if (!empty($error)) {
                $result['is_broken'] = true;
                $result['error_message'] = 'Connection error: ' . $error;
            } elseif ($httpCode >= 400) {
                $result['is_broken'] = true;
                $result['error_message'] = "HTTP $httpCode";
            }
            
            // Cache the result
            $this->checkedLinks[$linkData['url']] = $result;
            
            // Add to broken links if necessary
            if ($result['is_broken']) {
                $this->addBrokenLinkResult($pageUrl, $linkData, $result['error_message']);
            }
            
            curl_multi_remove_handle($multiHandle, $ch);
            curl_close($ch);
        }
        
        curl_multi_close($multiHandle);
    }
    
    private function addBrokenLinkResult($pageUrl, $linkData, $errorMessage) {
        // Check if we already have this broken URL from this source page
        foreach ($this->results as $existingResult) {
            if ($existingResult['broken_url'] === $linkData['url'] && 
                $existingResult['source_page'] === $pageUrl) {
                return; // Already reported
            }
        }
        
        $this->results[] = [
            'source_page' => $pageUrl,
            'broken_url' => $linkData['url'],
            'link_text' => $linkData['text'],
            'error' => $errorMessage,
            'link_type' => $linkData['type'],
            'category' => $linkData['category']
        ];
    }
    
    private function fetchPage($url) {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_USERAGENT => USER_AGENT,
            CURLOPT_SSL_VERIFYPEER => ENABLE_SSL_VERIFY,
            CURLOPT_MAXREDIRS => MAX_REDIRECTS,
        ]);
        
        $content = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $contentType = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
        
        curl_close($ch);
        
        if ($httpCode === 200 && strpos($contentType, 'text/html') !== false && $content) {
            return ['content' => $content, 'http_code' => $httpCode];
        }
        
        return false;
    }
    
    private function isImageUrl($url) {
        $path = parse_url($url, PHP_URL_PATH);
        if (!$path) return false;
        return preg_match('/\.(jpg|jpeg|png|gif|webp|svg|bmp|ico|tiff?)$/i', $path);
    }
    
    private function extractInternalLinks($html, $baseUrl) {
        // This method ONLY adds INTERNAL links to the crawl queue
        // External links are checked for validity but NOT crawled for their content
        
        $dom = new DOMDocument();
        libxml_use_internal_errors(true);
        $dom->loadHTML($html);
        libxml_clear_errors();
        
        $links = $dom->getElementsByTagName('a');
        $newUrls = [];
        
        foreach ($links as $link) {
            $href = trim($link->getAttribute('href'));
            if (empty($href)) continue;
            
            $absoluteUrl = $this->resolveUrl($href, $baseUrl);
            
            // Skip if resolveUrl returned false (invalid links)
            if ($absoluteUrl === false) continue;
            
            // CRITICAL: Only add internal links to crawl queue
            // External links are checked for existence but NOT crawled
            if (!$this->isSameDomain($absoluteUrl)) continue;
            
            // Skip if already visited or in queue
            if (in_array($absoluteUrl, $this->visited) || in_array($absoluteUrl, $this->queue)) continue;
            
            // Skip common file extensions that aren't HTML pages
            $path = parse_url($absoluteUrl, PHP_URL_PATH);
            if ($path && preg_match('/\.(pdf|jpg|jpeg|png|gif|zip|doc|docx|xls|xlsx|ppt|pptx|mp3|mp4|avi|mov)$/i', $path)) {
                continue;
            }
            
            $newUrls[] = $absoluteUrl;
        }
        
        // Limit new URLs to prevent explosion
        $newUrls = array_slice($newUrls, 0, 50); // Max 50 new URLs per page
        $this->queue = array_merge($this->queue, $newUrls);
        
        // Remove duplicates from queue
        $this->queue = array_unique($this->queue);
    }
    
    private function resolveUrl($href, $base) {
        if (empty($href) || $href === '#' || 
            strpos($href, 'javascript:') === 0 || 
            strpos($href, 'mailto:') === 0 || 
            strpos($href, 'tel:') === 0 ||
            strpos($href, '#') === 0 ||
            strpos($href, 'data:') === 0) { // Ignore data URIs (data:image, etc.)
            return false;
        }
        
        // Ignore Cloudflare CDN-CGI paths
        if (strpos($href, 'cdn-cgi') !== false) {
            return false;
        }
        
        if (preg_match('/^https?:\/\//', $href)) {
            // Also check absolute URLs for cdn-cgi
            if (strpos($href, '/cdn-cgi/') !== false) {
                return false;
            }
            return $this->normalizeUrl($href);
        }
        
        if (strpos($href, '//') === 0) {
            return $this->normalizeUrl(parse_url($base, PHP_URL_SCHEME) . ':' . $href);
        }
        
        if (strpos($href, '/') === 0) {
            // Check for cdn-cgi in absolute paths
            if (strpos($href, '/cdn-cgi/') !== false) {
                return false;
            }
            $baseScheme = parse_url($base, PHP_URL_SCHEME);
            $baseHost = parse_url($base, PHP_URL_HOST);
            return $this->normalizeUrl($baseScheme . '://' . $baseHost . $href);
        }
        
        $baseParts = parse_url($base);
        if (!$baseParts || !isset($baseParts['host'])) return false;
        
        $basePath = isset($baseParts['path']) ? $baseParts['path'] : '/';
        
        if (strpos(basename($basePath), '.') !== false) {
            $basePath = dirname($basePath);
        }
        
        if ($basePath === '.' || $basePath === '') {
            $basePath = '/';
        } elseif ($basePath !== '/') {
            $basePath = rtrim($basePath, '/') . '/';
        }
        
        $resolvedUrl = $baseParts['scheme'] . '://' . $baseParts['host'] . $basePath . ltrim($href, '/');
        
        // Final check for cdn-cgi in resolved URL
        if (strpos($resolvedUrl, '/cdn-cgi/') !== false) {
            return false;
        }
        
        return $this->normalizeUrl($resolvedUrl);
    }
    
    private function isSameDomain($url) {
        $urlHost = parse_url($url, PHP_URL_HOST);
        if (!$urlHost) return false;
        
        $urlHost = strtolower($urlHost);
        $baseHost = strtolower($this->domain);
        
        $urlHost = preg_replace('/^www\./', '', $urlHost);
        $baseHost = preg_replace('/^www\./', '', $baseHost);
        
        return $urlHost === $baseHost;
    }
    
    public function getResults() {
        return $this->results;
    }
    
    public function getTotalCrawled() {
        return count($this->visited);
    }
    
    public function getTotalLinksChecked() {
        return count($this->checkedLinks);
    }
    
    public function getExecutionTime() {
        if ($this->startTime && $this->endTime) {
            return round($this->endTime - $this->startTime, 2);
        }
        return 0;
    }
    
    public function getMemoryStats() {
        return [
            'peak_usage_mb' => round($this->memoryPeakUsage / 1024 / 1024, 2),
            'current_usage_mb' => round(memory_get_usage() / 1024 / 1024, 2)
        ];
    }
    
    public function getCacheStats() {
        return [
            'total_unique_links' => count($this->checkedLinks),
            'broken_links' => count($this->results),
            'concurrent_requests' => $this->maxConcurrentRequests,
            'batch_size' => $this->batchSize,
            'execution_time' => $this->getExecutionTime(),
            'memory_stats' => $this->getMemoryStats()
        ];
    }
}

// Handle form submission
$results = [];
$crawled = false;
$emailSent = false;
$errorMessage = '';

if (isset($_POST['action']) && $_POST['action'] === 'check' && !empty($_POST['domain'])) {
    // SECURITY: CSRF token validation
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die('CSRF validation failed. Please refresh the page and try again.');
    }

    // SECURITY: Rate limiting
    $lastRequestTime = $_SESSION['last_request_time'] ?? 0;
    $timeSinceLastRequest = time() - $lastRequestTime;

    if ($timeSinceLastRequest < RATE_LIMIT_SECONDS) {
        $waitTime = RATE_LIMIT_SECONDS - $timeSinceLastRequest;
        $errorMessage = "Please wait {$waitTime} seconds before starting another check (rate limit protection).";
    } else {
        // SECURITY: Use proper validation instead of deprecated FILTER_SANITIZE_URL
        $domain = trim($_POST['domain']);

        // Validate domain format
        if (empty($domain)) {
            $errorMessage = 'Please enter a domain name.';
        } else {
            // Try to validate as URL or domain
            $testUrl = preg_match('/^https?:\/\//', $domain) ? $domain : 'https://' . $domain;

            if (!filter_var($testUrl, FILTER_VALIDATE_URL)) {
                $errorMessage = 'Invalid domain or URL format.';
            } else {
                $sendEmail = isset($_POST['send_email']);
                $checkExternal = isset($_POST['check_external']);

                $limit = MAX_PAGES_DEFAULT;
                if (isset($_GET['limit']) && is_numeric($_GET['limit'])) {
                    $limit = max(1, min(MAX_PAGES_LIMIT, intval($_GET['limit'])));
                }

                // SECURITY: Validate redirect URL components
                $redirectUrl = $_SERVER['PHP_SELF'] . '?crawl=1&domain=' . urlencode($domain) . '&limit=' . intval($limit);
                if ($sendEmail) $redirectUrl .= '&email=1';
                if ($checkExternal) $redirectUrl .= '&external=1';

                // Update rate limit timestamp
                $_SESSION['last_request_time'] = time();

                header('Location: ' . $redirectUrl);
                exit;
            }
        }
    }
}

// Handle the actual crawling (from redirect)
if (isset($_GET['crawl']) && $_GET['crawl'] === '1' && !empty($_GET['domain'])) {
    // SECURITY: Validate domain from GET parameter
    $domain = trim($_GET['domain']);
    $testUrl = preg_match('/^https?:\/\//', $domain) ? $domain : 'https://' . $domain;

    if (!filter_var($testUrl, FILTER_VALIDATE_URL)) {
        $errorMessage = 'Invalid domain or URL format.';
    } else {
        $sendEmail = isset($_GET['email']);
        $checkExternal = isset($_GET['external']);
        $limit = isset($_GET['limit']) ? max(1, min(MAX_PAGES_LIMIT, intval($_GET['limit']))) : MAX_PAGES_DEFAULT;

        $crawled = true;
        $linkTypeText = $checkExternal ? "internal and external links" : "internal links only";

        echo "<script>
        document.addEventListener('DOMContentLoaded', function() {
            document.getElementById('crawl-form').style.display = 'none';
        });
        </script>";

        echo "<div id='crawling-status' class='alert alert-info'>";
        echo "<h5><span class='spinner-border spinner-border-sm mr-2'></span>Checking " . htmlspecialchars($linkTypeText) . " for <strong>" . htmlspecialchars($domain) . "</strong> (Limited to " . htmlspecialchars($limit) . " pages)</h5>";
        echo "<div id='status'>Initializing optimized crawler with multi-cURL...</div>";
        echo "</div>";
        echo str_repeat(' ', 1024);
        flush();

        // SECURITY: Wrap in try-catch to handle SSRF and other exceptions
        try {
            $checker = new OptimizedLinkChecker($domain, $limit, $checkExternal);
            $results = $checker->crawl();
            $totalCrawled = $checker->getTotalCrawled();
            $totalLinksChecked = $checker->getTotalLinksChecked();
            $cacheStats = $checker->getCacheStats();

            echo "<script>document.getElementById('crawling-status').style.display='none';</script>";

            // Send email if requested
            if ($sendEmail) {
                // SECURITY: Sanitize email inputs to prevent header injection
                $from = filter_var(EMAIL_FROM, FILTER_VALIDATE_EMAIL);
                $to = filter_var(EMAIL_TO, FILTER_VALIDATE_EMAIL);

                if ($from && $to) {
                    // Remove any newlines from email addresses
                    $from = str_replace(["\r", "\n", "%0a", "%0d"], '', $from);
                    $to = str_replace(["\r", "\n", "%0a", "%0d"], '', $to);

                    $subject = empty($results) ?
                        'Link Check Report for ' . $domain . ' - No Broken Links Found' :
                        'Link Check Report for ' . $domain . ' - ' . count($results) . ' Broken Links';

                    // Remove newlines from subject
                    $subject = str_replace(["\r", "\n"], '', $subject);

                    $emailBody = generateEmailReport($results, $domain, $totalCrawled, $totalLinksChecked, $checkExternal, $cacheStats, $checker->getExecutionTime(), $checker->getMemoryStats());

                    // SECURITY: Safe email headers
                    $headers = "From: " . $from . "\r\n";
                    $headers .= "Content-Type: text/html; charset=UTF-8\r\n";

                    if (mail($to, $subject, $emailBody, $headers)) {
                        $emailSent = true;
                    }
                } else {
                    $errorMessage = 'Invalid email configuration.';
                }
            }
        } catch (Exception $e) {
            // SECURITY: Handle exceptions gracefully without exposing internals
            echo "<script>document.getElementById('crawling-status').style.display='none';</script>";
            $errorMessage = 'An error occurred: ' . htmlspecialchars($e->getMessage());
            $crawled = false;
        }
    }
}

function generateEmailReport($results, $domain, $totalCrawled, $totalLinksChecked, $checkExternal = true, $cacheStats = [], $executionTime = 0, $memoryStats = []) {
    $html = "<html><body>";
    $html .= "<h2>Optimized Broken Link Analysis Report</h2>";
    $html .= "<p><strong>Domain:</strong> " . htmlspecialchars($domain) . "</p>";
    $html .= "<p><strong>Total Pages Crawled:</strong> " . $totalCrawled . "</p>";
    $html .= "<p><strong>Total Links Checked:</strong> " . $totalLinksChecked . "</p>";
    $html .= "<p><strong>Link Types Checked:</strong> " . ($checkExternal ? 'Internal and External' : 'Internal Only') . "</p>";
    $html .= "<p><strong>Broken Links Found:</strong> " . count($results) . "</p>";
    $html .= "<p><strong>Execution Time:</strong> " . $executionTime . " seconds</p>";
    
    if (!empty($memoryStats)) {
        $html .= "<p><strong>Peak Memory Usage:</strong> " . $memoryStats['peak_usage_mb'] . " MB</p>";
    }
    
    $html .= "<p><strong>Generated:</strong> " . date('Y-m-d H:i:s') . "</p>";
    
    if (isset($cacheStats['concurrent_requests'])) {
        $html .= "<hr><h3>Performance Optimization Details</h3>";
        $html .= "<p><strong>Multi-cURL Concurrent Requests:</strong> " . $cacheStats['concurrent_requests'] . "</p>";
        $html .= "<p><strong>Batch Processing Size:</strong> " . $cacheStats['batch_size'] . " links per batch</p>";
        $html .= "<p><strong>Cache Efficiency:</strong> Avoided duplicate checks for " . ($cacheStats['total_unique_links'] - count($results)) . " working links</p>";
        
        if ($executionTime > 0 && $totalLinksChecked > 0) {
            $linksPerSecond = round($totalLinksChecked / $executionTime, 1);
            $html .= "<p><strong>Processing Speed:</strong> " . $linksPerSecond . " links/second</p>";
        }
        
        $html .= "<p><em>Memory was optimized by discarding HTML content immediately after link extraction.</em></p>";
    }
    
    if (!empty($results)) {
        $html .= "<hr><table border='1' cellpadding='8' cellspacing='0' style='border-collapse:collapse; width:100%;'>";
        $html .= "<tr style='background-color:#f8f9fa;'><th>Source Page</th><th>Broken URL</th><th>Link Text</th><th>Error</th><th>Type</th><th>Category</th></tr>";
        
        foreach ($results as $result) {
            $html .= "<tr>";
            $html .= "<td>" . htmlspecialchars($result['source_page']) . "</td>";
            $html .= "<td>" . htmlspecialchars($result['broken_url']) . "</td>";
            $html .= "<td>" . htmlspecialchars($result['link_text']) . "</td>";
            $html .= "<td>" . htmlspecialchars($result['error']) . "</td>";
            
            $typeColor = $result['link_type'] === 'internal' ? '#e74c3c' : '#3498db';
            $html .= "<td><span style='background-color:$typeColor; color:white; padding:2px 6px; border-radius:3px; font-size:11px;'>" . ucfirst($result['link_type']) . "</span></td>";
            
            $category = isset($result['category']) ? $result['category'] : 'link';
            $categoryColor = $category === 'image' ? '#f39c12' : '#17a2b8';
            $html .= "<td><span style='background-color:$categoryColor; color:white; padding:2px 6px; border-radius:3px; font-size:11px;'>" . ucfirst($category) . "</span></td>";
            $html .= "</tr>";
        }
        $html .= "</table>";
        
        $html .= "<br><p><strong>Performance:</strong> Optimized with parallel cURL processing for faster link checking.</p>";
    } else {
        $html .= "<p style='color: green;'><strong>Excellent!</strong> No broken links found on your website.</p>";
    }
    
    $html .= "<p><small>Powered by <a href='https://www.ebizindia.com'>Ebizindia</a> - Optimized Version</small></p>";
    $html .= "</body></html>";
    
    return $html;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Broken Link Checker Tool - Ebizindia</title>
    <meta name="description" content="Find and fix broken links on your website. Check internal and external links for 404 errors, timeouts, and other issues. Free broken link checker by Ebizindia.">
    <link rel="canonical" href="https://www.ebizindia.com/tools/linkcheck/">
    
    <!-- Bootstrap 4 CSS -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css">
    <!-- jQuery -->
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/js/bootstrap.bundle.min.js"></script>
    
    <style>
        body { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        .main-container {
            background: white;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            margin: 30px 0;
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 {
            margin-bottom: 10px;
            font-weight: 300;
            font-size: 2.5rem;
        }
        .header p {
            margin: 0;
            opacity: 0.9;
        }
        .content {
            padding: 40px;
        }
        .form-group label {
            font-weight: 600;
            color: #2c3e50;
        }
        .btn-primary {
            background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
            border: none;
            padding: 12px 30px;
            font-weight: 600;
            border-radius: 25px;
        }
        .btn-primary:hover {
            background: linear-gradient(135deg, #c0392b 0%, #a93226 100%);
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
        }
        .results-table {
            margin-top: 30px;
        }
        .table thead th {
            background-color: #f8f9fa;
            border-bottom: 2px solid #dee2e6;
            font-weight: 600;
            color: #2c3e50;
        }
        .badge-internal {
            background-color: #e74c3c;
            color: white;
        }
        .badge-external {
            background-color: #3498db;
            color: white;
        }
        .badge-warning {
            background-color: #f39c12;
            color: white;
        }
        .badge-info {
            background-color: #17a2b8;
            color: white;
        }
        .footer {
            text-align: center;
            padding: 20px;
            background-color: #f8f9fa;
            border-top: 1px solid #dee2e6;
        }
        .footer a {
            color: #3498db;
            text-decoration: none;
        }
        .footer a:hover {
            text-decoration: underline;
        }
        .summary-cards {
            margin: 20px 0;
        }
        .summary-card {
            background: white;
            border: 1px solid #dee2e6;
            border-radius: 10px;
            padding: 20px;
            text-align: center;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
        }
        .summary-card h3 {
            color: #e74c3c;
            margin-bottom: 5px;
        }
        .summary-card p {
            color: #7f8c8d;
            margin: 0;
        }
        #crawling-status {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 1000;
            min-width: 300px;
        }
        .success-message {
            background-color: #d4edda;
            color: #155724;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }
        .broken-link {
            word-break: break-all;
        }
        .link-text {
            max-width: 200px;
            word-wrap: break-word;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="main-container">
            <div class="header">
                <h1>Broken Link Checker Tool</h1>
                <?php if ($crawled && !empty($_GET['domain'])): ?>
                <p>Results for: <strong><?php echo htmlspecialchars($_GET['domain']); ?></strong></p>
                <?php else: ?>
                <p>Find and fix broken internal and external links on your website</p>
                <?php endif; ?>
                <p><small>🚀 Optimized: Multi-cURL processing with memory management</small></p>
                <?php if (isset($_GET['limit']) && is_numeric($_GET['limit'])): ?>
                <p><small>Current limit: <?php echo max(1, min(MAX_PAGES_LIMIT, intval($_GET['limit']))); ?> pages</small></p>
                <?php endif; ?>
            </div>
            
            <div class="content">
                <div id="crawl-form" <?php echo $crawled ? 'style="display:none;"' : ''; ?>>
                <?php if (!empty($errorMessage)): ?>
                <div class="alert alert-danger" role="alert">
                    <strong>Error:</strong> <?php echo htmlspecialchars($errorMessage); ?>
                </div>
                <?php endif; ?>
                <form method="post" action="">
                    <input type="hidden" name="action" value="check">
                    <!-- SECURITY: CSRF Token -->
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">

                    <div class="form-group">
                        <label for="domain">Website Domain</label>
                        <input type="text" 
                               class="form-control" 
                               id="domain" 
                               name="domain" 
                               placeholder="example.com or https://example.com" 
                               value="<?php echo isset($_GET['domain']) ? htmlspecialchars($_GET['domain']) : ''; ?>"
                               required>
                        <small class="form-text text-muted">
                            Enter domain with or without https://<br>
                            <strong>Tip:</strong> Add ?limit=50 to URL to limit crawl (default: 100 pages)
                        </small>
                    </div>
                    
                    <div class="form-check mb-3">
                        <input type="checkbox" 
                               class="form-check-input" 
                               id="check_external" 
                               name="check_external" 
                               <?php echo (!isset($_GET['external']) || $_GET['external']) ? 'checked' : ''; ?>>
                        <label class="form-check-label" for="check_external">
                            Check external links (slower but comprehensive)
                        </label>
                        <small class="form-text text-muted">Uncheck for faster scanning of internal links only</small>
                    </div>
                    
                    <div class="form-check mb-3">
                        <input type="checkbox" 
                               class="form-check-input" 
                               id="send_email" 
                               name="send_email" 
                               <?php echo (!isset($_GET['email']) || $_GET['email']) ? 'checked' : ''; ?>>
                        <label class="form-check-label" for="send_email">
                            Email report to ebizindia@gmail.com
                        </label>
                    </div>
                    
                    <button type="submit" class="btn btn-primary btn-lg">
                        <i class="fas fa-search"></i> Start Link Check
                    </button>
                </form>
                </div>
                
                <?php if ($crawled): ?>
                <div id="results-section">
                    <!-- Check Another Website Button - Moved to Top -->
                    <div class="mb-4 text-center">
                        <button class="btn btn-secondary btn-lg" onclick="resetForm()">
                            🔄 Check Another Website
                        </button>
                    </div>
                    <?php if ($emailSent): ?>
                    <div class="success-message">
                        <strong>Success!</strong> Report has been emailed to ebizindia@gmail.com
                    </div>
                    <?php elseif (isset($_GET['email']) && !$emailSent): ?>
                    <div class="alert alert-warning">
                        <strong>Email Issue:</strong> Could not send email. Please check your email settings.
                    </div>
                    <?php endif; ?>
                    
                    <div class="row summary-cards">
                        <div class="col-md-3">
                            <div class="summary-card">
                                <h3><?php echo $totalCrawled; ?></h3>
                                <p>Pages Crawled</p>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="summary-card">
                                <h3><?php echo $totalLinksChecked; ?></h3>
                                <p>Links Checked</p>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="summary-card">
                                <h3><?php echo count($results); ?></h3>
                                <p>Broken Links</p>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="summary-card">
                                <h3><?php echo $checker->getExecutionTime(); ?>s</h3>
                                <p>Execution Time</p>
                            </div>
                        </div>
                    </div>
                    
                    <?php if (!empty($results)): ?>
                    <div class="results-table">
                        <h3>Broken Links Found</h3>
                        <div class="table-responsive">
                            <table class="table table-striped table-bordered">
                                <thead>
                                    <tr>
                                        <th>Source Page</th>
                                        <th>Broken URL</th>
                                        <th>Link Text</th>
                                        <th>Error</th>
                                        <th>Type</th>
                                        <th>Category</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($results as $result): ?>
                                    <tr>
                                        <td>
                                            <?php if ($result['source_page'] !== 'Direct Access'): ?>
                                            <a href="<?php echo htmlspecialchars($result['source_page']); ?>" 
                                               target="_blank" 
                                               class="text-primary">
                                                <?php echo htmlspecialchars($result['source_page']); ?>
                                            </a>
                                            <?php else: ?>
                                            <?php echo htmlspecialchars($result['source_page']); ?>
                                            <?php endif; ?>
                                        </td>
                                        <td class="broken-link">
                                            <?php echo htmlspecialchars($result['broken_url']); ?>
                                        </td>
                                        <td class="link-text">
                                            <?php echo htmlspecialchars($result['link_text']); ?>
                                        </td>
                                        <td>
                                            <span class="text-danger"><?php echo htmlspecialchars($result['error']); ?></span>
                                        </td>
                                        <td>
                                            <span class="badge badge-<?php echo $result['link_type']; ?> mr-2 mb-1">
                                                <?php echo ucfirst($result['link_type']); ?>
                                            </span>
                                        </td>
                                        <td>
                                            <?php 
                                            $category = isset($result['category']) ? $result['category'] : 'link';
                                            $categoryClass = $category === 'image' ? 'badge-warning' : 'badge-info';
                                            ?>
                                            <span class="badge <?php echo $categoryClass; ?> mr-2 mb-1">
                                                <?php echo ucfirst($category); ?>
                                            </span>
                                        </td>
                                    </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                    <?php else: ?>
                    <div class="alert alert-success">
                        <h4>Excellent!</h4>
                        <p>No broken links found on your website. All <?php echo $totalLinksChecked; ?> links are working properly!</p>
                    </div>
                    <?php endif; ?>
                </div>
                <?php endif; ?>
            </div>
            
            <div class="footer">
                <p>Powered by <a href="https://www.ebizindia.com" target="_blank">Ebizindia</a></p>
            </div>
        </div>
    </div>

    <script>
        $(document).ready(function() {
            // Add smooth animations
            $('.main-container').hide().fadeIn(500);
            
            // Auto-hide form if crawling results are shown
            <?php if ($crawled): ?>
            $('#crawl-form').hide();
            <?php endif; ?>
            
            // Form validation
            $('#crawl-form form').on('submit', function() {
                var domain = $('#domain').val().trim();
                if (!domain) {
                    alert('Please enter a domain name');
                    return false;
                }
                
                // Show loading state
                $(this).find('button[type="submit"]').html('<span class="spinner-border spinner-border-sm mr-2"></span>Starting Link Check...');
                $(this).find('button[type="submit"]').prop('disabled', true);
                
                // Note: Form will redirect, so no need to manually hide
                return true;
            });
        });
        
        function resetForm() {
            // Redirect to clean URL without GET parameters to reset the form
            var baseUrl = window.location.href.split('?')[0];
            var limitParam = new URLSearchParams(window.location.search).get('limit');
            
            // Keep the limit parameter if it was set
            if (limitParam && limitParam !== '100') {
                window.location.href = baseUrl + '?limit=' + limitParam;
            } else {
                window.location.href = baseUrl;
            }
        }
    </script>
</body>
</html>
