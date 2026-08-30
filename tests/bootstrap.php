<?php

/**
 * This file is part of the PHP WebRTC package.
 *
 * (c) Amin Yazdanpanah <https://www.aminyazdanpanah.com/#contact>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use DG\BypassFinals;

require __DIR__ . '/../vendor/autoload.php';

// Several production classes (e.g. RTCDtlsTransport) are declared "final",
// which PHPUnit's mock generator cannot double. BypassFinals strips the "final"
// keyword at autoload time so the test suite can mock them without loosening
// production code.
//
// Whitelist only our own sources: left unrestricted it also rewrites PHPUnit's
// vendor classes and strips their "readonly", which breaks their inheritance
// at load time.
BypassFinals::setWhitelist([realpath(__DIR__ . '/../src') . '/*']);
BypassFinals::enable();
