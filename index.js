/*!
* SecDownload.js
*
* Copyright (c) 2014 Indigo Development Team http://indigophp.com
* Licensed under the MIT licence. See LICENSE file
* Version 0.0.1
*/

"use strict";

var fs = require("fs");
var url = require("url");
var events = require("events");
var php = require('phpjs');
var crypto = require('crypto');
var path = require('path');
var mime = require('mime');

var settings = {};

try {
  settings = require("konphyg")(__dirname + "/config/")("secdownload");
} catch (e) {
  console.error(e);
}

var handler = new events.EventEmitter();

var secDownload = function (req, res) {
	var hash = crypto.createHash('md5');
	var uri = parseUrl(req);
	var uriPrefix = php.trim(settings.uriPrefix, '/');

	// Security checks.
	if (!uri) {
		handler.emit("badRequest", res);
		return false;
	} else if (uri.search(/^\.\.?|^\/|^\\/) !== -1) {
		handler.emit("security", res, { message: uri });
		return false;
	} else if (uri.substring(0, uriPrefix.length) !== uriPrefix) {
		// This will trigger if wrong slashes are used. Change?
		handler.emit("security", res, { message: uri });
		return false;
	}

	uri = uri.substring(uriPrefix.length + 1);

	var info = php.explode('/', uri, 3);

	info = {
		"file": path.normalize(info[2]),
		"time": {
			"hex": info[1],
			"dec": parseInt(info[1], 16)
		},
		"hash": info[0]
	};

	hash.update(settings.secret + '/' + info.file + info.time.hex);
	hash = hash.digest('hex');

	if (Math.abs(php.time() - info.time.dec) > settings.timeout) {
		handler.emit("urlGone", res, { message: uri });
		return false;
	} else if (hash !== info.hash) {
		handler.emit("security", res, { message: uri });
		return false;
	}

	var file = path.join(settings.rootPath, info.file);

	if (!fs.statSync(file).isFile()) {
		handler.emit("badFile", res, { message: file });
		return false;
	} else {
		handler.emit("download", res, file);
	}

	return true;
};

secDownload.settings = function (s) {
	for (var prop in s) { settings[prop] = s[prop]; }
	return secDownload;
};

secDownload.on = function (event, callback) {
	handler.removeAllListeners(event).on(event, callback);
	return secDownload;
};

var parseUrl = function (req) {
	var uri = url.parse(req.url, true);
	uri = typeof uri.pathname === "string" ? uri.pathname.substring(1) : undefined;

	if (uri) {
		try {
			return php.rtrim(decodeURIComponent(uri), "/");
		} catch (e) {
			// Can throw URI malformed exception.
			return undefined;
		}
	}
}

var errorHeader = function (res, code) {
	var header = {
		"Content-Type": "text/html",
		"Server": settings.server
	};

	res.writeHead(code, header);
};

handler.on("badFile", function (res, e) {
	errorHeader(res, 404);
	res.end("<!DOCTYPE html><html lang=\"en\">" +
		"<head><title>404 Not found</title></head>" +
		"<body>" +
		"<h1>Ooh dear</h1>" +
		"<p>Sorry, I can't find that file. Could you check again?</p>" +
		"</body></html>");
	console.error("404 Bad File - " + (e ? e.message : ""));
});

handler.on("security", function (res, e) {
	errorHeader(res, 403);
	res.end("<!DOCTYPE html><html lang=\"en\">" +
		"<head><title>403 Forbidden</title></head>" +
		"<body>" +
		"<h1>Hey!</h1>" +
		"<p>Stop trying to hack my server!</p>" +
		"</body></html>");
	console.error("403 Security - " + (e ? e.message : ""));
});

handler.on("badRequest", function (res, e) {
	errorHeader(res, 400);
	res.end("<!DOCTYPE html><html lang=\"en\">" +
		"<head><title>400 Bad request</title></head>" +
		"<body>" +
		"<h1>Wut?</h1>" +
		"<p>I couldn't understand that I'm afraid; the syntax appears malformed.</p>" +
		"</body></html>");
	console.error("400 Bad Request - " + (e ? e.message : ""));
});

handler.on("urlGone", function (res, e) {
	errorHeader(res, 410);
	res.end("<!DOCTYPE html><html lang=\"en\">" +
		"<head><title>410 Gone</title></head>" +
		"<body>" +
		"<h1>URL is not available</h1>" +
		"<p>URL is not available anymore.</p>" +
		"</body></html>");
	console.error("410 Gone - " + (e ? e.message : ""));
});

handler.on("download", function (res, file) {
	res.setHeader("Content-Disposition", "attachment; filename=" + path.basename(file));
	res.setHeader("Content-Type", mime.lookup(file));
	res.setHeader("Expires", "19 Nov 1981 08:52:00 GMT");
	res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, post-check=0, pre-check=0");
	res.setHeader("Pragma", "no-cache");

	var stream = fs.createReadStream(file);
	stream.pipe(res);
});

module.exports = secDownload;
