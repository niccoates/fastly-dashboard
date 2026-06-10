require("dotenv").config();

const crypto = require("crypto");
const express = require("express");
const path = require("path");

const app = express();
const port = process.env.PORT || 3000;
const host = process.env.HOST || "127.0.0.1";

const FASTLY_API_KEY = process.env.FASTLY_API_KEY || "";
const FASTLY_WORKSPACE_ID = process.env.FASTLY_WORKSPACE_ID || "";
const REQUEST_DELAY_MS = Number.parseInt(process.env.REQUEST_DELAY_MS || "250", 10);
const requestDelayMs = Number.isFinite(REQUEST_DELAY_MS) ? REQUEST_DELAY_MS : 250;
const ALLOWED_IPS = parseAllowedIps(process.env.ALLOWED_IPS);
const INTERNAL_PASSWORD = process.env.INTERNAL_PASSWORD || "";
const authCookieName = "fastly_dashboard_auth";
const authToken = INTERNAL_PASSWORD
  ? crypto.createHash("sha256").update(`fastly-dashboard:${INTERNAL_PASSWORD}`).digest("hex")
  : "";

const buckets = [
  {
    name: "Total successful requests",
    template: "server:{server} {paths} from:{from} until:{until} httpcode:200",
    total: true
  },
  {
    name: "Human visitors - strict candidates",
    template:
      'server:{server} {paths} from:{from} until:{until} httpcode:200 requestheader:Sec-Fetch-User:"?1" -tag:SUSPECTED-BOT -tag:SUSPECTED-BAD-BOT -tag:DATACENTER sort:time-desc',
    positive: true
  },
  {
    name: "LLM / AI crawler and fetcher samples",
    template:
      "server:{server} {paths} from:{from} until:{until} httpcode:200 tag:VERIFIED-BOT.AI-FETCHER tag:VERIFIED-BOT.AI-CRAWLER tag:SUSPECTED-BOT.AI-FETCHER tag:SUSPECTED-BOT.AI-CRAWLER sort:time-desc",
    positive: true
  },
  {
    name: "Status aggregators",
    template:
      "server:{server} {paths} from:{from} until:{until} httpcode:200 useragent:~StatusGator useragent:~PulseBoard useragent:~ReliabilityAPI useragent:~VendorMonitor useragent:~StatusMonitor sort:time-desc",
    positive: true
  },
  {
    name: "Synthetic monitoring samples",
    template:
      "server:{server} {paths} from:{from} until:{until} httpcode:200 useragent:~Catchpoint useragent:~uptime-monitor useragent:~UptimeRobot useragent:~Pingdom useragent:~StatusCake useragent:~Datadog useragent:~Site24x7 useragent:~Checkly useragent:~Uptrends useragent:~BetterStack sort:time-desc",
    positive: true
  },
  {
    name: "Known search crawlers",
    template:
      "server:{server} {paths} from:{from} until:{until} httpcode:200 tag:VERIFIED-BOT.SEARCH-ENGINE-CRAWLER sort:time-desc",
    positive: true
  },
  {
    name: "Enterprise automation / customer polling samples",
    template:
      'server:{server} {paths} from:{from} until:{until} httpcode:200 useragent:"Splunk (Default)" useragent:~PowerShell useragent:~curl useragent:~python useragent:~Go-http-client useragent:~Java useragent:~Wget sort:time-desc',
    positive: true
  },
  {
    name: "Bad bot / scanner / impersonator",
    template:
      "server:{server} {paths} from:{from} until:{until} httpcode:200 tag:SUSPECTED-BAD-BOT tag:SUSPECTED-BAD-BOT.HEADLESS tag:SUSPECTED-BOT.HEADLESS tag:SCANNER tag:TORNODE sort:time-desc",
    positive: true
  }
];

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(requireAllowedIp);

app.get("/login", (req, res) => {
  if (!INTERNAL_PASSWORD || isAuthenticated(req)) {
    res.redirect("/");
    return;
  }

  res.render("login", {
    error: null
  });
});

app.post("/login", (req, res) => {
  if (!INTERNAL_PASSWORD) {
    res.redirect("/");
    return;
  }

  if (passwordMatches(req.body.password || "")) {
    res.cookie(authCookieName, authToken, {
      httpOnly: true,
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 12
    });
    res.redirect("/");
    return;
  }

  res.status(401).render("login", {
    error: "Incorrect password."
  });
});

app.post("/logout", (req, res) => {
  res.clearCookie(authCookieName);
  res.redirect("/login");
});

app.get("/debug/ip", (req, res) => {
  res.json({
    ip: req.ip,
    socketRemoteAddress: req.socket.remoteAddress,
    xForwardedFor: req.headers["x-forwarded-for"],
    xRealIp: req.headers["x-real-ip"],
    headers: req.headers,
  });
});

app.use(requirePassword);

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function parseAllowedIps(value) {
  return new Set(
    String(value || "")
      .split(",")
      .map((ip) => normalizeIp(ip.trim()))
      .filter(Boolean)
  );
}

function normalizeIp(ip) {
  return String(ip || "").replace(/^::ffff:/, "").trim();
}

function getClientIp(req) {
  const forwardedFor = req.get("x-forwarded-for") || "";
  const firstForwardedIp = forwardedFor.split(",")[0]?.trim();
  return normalizeIp(firstForwardedIp || req.ip || req.socket.remoteAddress || "");
}

function parseCookies(cookieHeader) {
  return String(cookieHeader || "")
    .split(";")
    .map((cookie) => cookie.trim())
    .filter(Boolean)
    .reduce((cookies, cookie) => {
      const separatorIndex = cookie.indexOf("=");

      if (separatorIndex === -1) {
        return cookies;
      }

      const name = cookie.slice(0, separatorIndex);
      const value = cookie.slice(separatorIndex + 1);
      cookies[name] = decodeURIComponent(value);
      return cookies;
    }, {});
}

function requireAllowedIp(req, res, next) {
  if (ALLOWED_IPS.size === 0) {
    next();
    return;
  }

  const clientIp = getClientIp(req);

  if (ALLOWED_IPS.has(clientIp)) {
    next();
    return;
  }

  res.status(403).send("Forbidden");
}

function timingSafeEqualString(left, right) {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);

  if (leftBuffer.length !== rightBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function passwordMatches(password) {
  return timingSafeEqualString(password, INTERNAL_PASSWORD);
}

function isAuthenticated(req) {
  if (!INTERNAL_PASSWORD) {
    return true;
  }

  const cookies = parseCookies(req.get("cookie"));
  return timingSafeEqualString(cookies[authCookieName] || "", authToken);
}

function requirePassword(req, res, next) {
  if (isAuthenticated(req)) {
    next();
    return;
  }

  if (req.path === "/run") {
    res.setHeader("Content-Type", "application/x-ndjson; charset=utf-8");
    res.status(401).write(`${JSON.stringify({ type: "validation-error", errors: ["Password required."] })}\n`);
    res.end();
    return;
  }

  res.redirect("/login");
}

function normalizeDateForFastly(dateValue) {
  return String(dateValue || "").replaceAll("-", "");
}

function buildPathFilter(pathsInput) {
  return String(pathsInput || "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((pathValue) => `path:${pathValue}`)
    .join(" ");
}

function buildQuery(template, form) {
  const replacements = {
    server: form.server.trim(),
    paths: buildPathFilter(form.paths),
    from: normalizeDateForFastly(form.from),
    until: normalizeDateForFastly(form.until)
  };

  return template
    .replaceAll("{server}", replacements.server)
    .replaceAll("{paths}", replacements.paths)
    .replaceAll("{from}", replacements.from)
    .replaceAll("{until}", replacements.until)
    .replace(/\s+/g, " ")
    .trim();
}

async function getFastlyCount({ workspaceId, token, query }) {
  const url = new URL(
    `https://api.fastly.com/ngwaf/v1/workspaces/${encodeURIComponent(workspaceId)}/requests`
  );
  url.searchParams.set("limit", "1");
  url.searchParams.set("q", query);

  const response = await fetch(url, {
    method: "GET",
    headers: {
      Accept: "application/json",
      "Fastly-Key": token
    }
  });

  const responseBody = await response.text();

  if (!response.ok) {
    const error = new Error(`Fastly API request failed with status ${response.status}`);
    error.status = response.status;
    error.body = responseBody;
    error.query = query;
    throw error;
  }

  const data = responseBody ? JSON.parse(responseBody) : {};
  return Number(data?.meta?.total || 0);
}

async function getFastlyCountWithRetry({ workspaceId, token, query }) {
  const maxAttempts = 2;
  let lastError;

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      return await getFastlyCount({ workspaceId, token, query });
    } catch (error) {
      lastError = error;

      if (!error.status || error.status < 500 || attempt === maxAttempts) {
        throw error;
      }

      await delay(Math.max(requestDelayMs, 1000));
    }
  }

  throw lastError;
}

function initialForm() {
  return {
    server: "status.broadcom.com",
    paths: "",
    from: "",
    until: ""
  };
}

function validateForm(form) {
  const errors = [];

  if (!FASTLY_API_KEY) errors.push("FASTLY_API_KEY is not set.");
  if (!FASTLY_WORKSPACE_ID) errors.push("FASTLY_WORKSPACE_ID is not set.");
  if (!form.server.trim()) errors.push("Server hostname is required.");
  if (!form.from) errors.push("From date is required.");
  if (!form.until) errors.push("Until date is required.");
  if (form.from && form.until && form.from > form.until) {
    errors.push("From date must be before or equal to until date.");
  }

  return errors;
}

app.get("/", (req, res) => {
  res.render("index", {
    form: initialForm(),
    workspaceId: FASTLY_WORKSPACE_ID,
    requestDelayMs,
    results: [],
    errors: [],
    apiError: null,
    submitted: false,
    passwordEnabled: Boolean(INTERNAL_PASSWORD)
  });
});

app.post("/", async (req, res) => {
  const form = {
    server: req.body.server || "",
    paths: req.body.paths || "",
    from: req.body.from || "",
    until: req.body.until || ""
  };

  const errors = validateForm(form);
  const results = [];
  let apiError = null;

  if (errors.length === 0) {
    for (const bucket of buckets) {
      try {
        const query = buildQuery(bucket.template, form);
        const total = await getFastlyCountWithRetry({
          workspaceId: FASTLY_WORKSPACE_ID,
          token: FASTLY_API_KEY,
          query
        });

        results.push({
          name: bucket.name,
          query,
          total,
          positive: bucket.positive,
          totalBucket: bucket.total
        });

        if (bucket !== buckets[buckets.length - 1] && requestDelayMs > 0) {
          await delay(requestDelayMs);
        }
      } catch (error) {
        const query = error.query || buildQuery(bucket.template, form);
        results.push({
          name: bucket.name,
          query,
          error: {
            status: error.status || "Unknown",
            body: error.body || error.message
          }
        });
      }
    }

    const totalSuccessful = results.find((result) => result.totalBucket)?.total;
    const positivelyIdentifiedTotal = results
      .filter((result) => result.positive)
      .reduce((sum, result) => sum + result.total, 0);

    if (typeof totalSuccessful === "number") {
      results.push({
        name: "Other automated / suspicious / unknown",
        query: "Not queried. Calculated locally as total successful requests minus identified buckets.",
        total: Math.max(0, totalSuccessful - positivelyIdentifiedTotal),
        calculated: true
      });
    } else {
      results.push({
        name: "Other automated / suspicious / unknown",
        query: "Calculation skipped because Total successful requests did not complete successfully.",
        error: {
          status: "Skipped",
          body: "The total successful requests bucket is required for this calculation."
        }
      });
    }
  }

  res.render("index", {
    form,
    workspaceId: FASTLY_WORKSPACE_ID,
    requestDelayMs,
    results,
    errors,
    apiError,
    submitted: true,
    passwordEnabled: Boolean(INTERNAL_PASSWORD)
  });
});

function writeJsonLine(res, payload) {
  res.write(`${JSON.stringify(payload)}\n`);
}

app.post("/run", async (req, res) => {
  const form = {
    server: req.body.server || "",
    paths: req.body.paths || "",
    from: req.body.from || "",
    until: req.body.until || ""
  };
  const errors = validateForm(form);

  res.setHeader("Content-Type", "application/x-ndjson; charset=utf-8");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("X-Accel-Buffering", "no");

  if (errors.length > 0) {
    writeJsonLine(res, { type: "validation-error", errors });
    res.end();
    return;
  }

  const results = [];

  for (const bucket of buckets) {
    const query = buildQuery(bucket.template, form);
    writeJsonLine(res, {
      type: "started",
      name: bucket.name,
      query
    });

    try {
      const total = await getFastlyCountWithRetry({
        workspaceId: FASTLY_WORKSPACE_ID,
        token: FASTLY_API_KEY,
        query
      });
      const result = {
        name: bucket.name,
        query,
        total,
        positive: bucket.positive,
        totalBucket: bucket.total
      };

      results.push(result);
      writeJsonLine(res, {
        type: "result",
        result
      });
    } catch (error) {
      writeJsonLine(res, {
        type: "api-error",
        result: {
          name: bucket.name,
          query,
          error: {
            status: error.status || "Unknown",
            body: error.body || error.message
          }
        }
      });
    }

    if (bucket !== buckets[buckets.length - 1] && requestDelayMs > 0) {
      await delay(requestDelayMs);
    }
  }

  const totalSuccessful = results.find((result) => result.totalBucket)?.total;
  const positivelyIdentifiedTotal = results
    .filter((result) => result.positive)
    .reduce((sum, result) => sum + result.total, 0);

  if (typeof totalSuccessful === "number") {
    writeJsonLine(res, {
      type: "result",
      result: {
        name: "Other automated / suspicious / unknown",
        query: "Not queried. Calculated locally as total successful requests minus identified buckets.",
        total: Math.max(0, totalSuccessful - positivelyIdentifiedTotal),
        calculated: true
      }
    });
  } else {
    writeJsonLine(res, {
      type: "api-error",
      result: {
        name: "Other automated / suspicious / unknown",
        query: "Calculation skipped because Total successful requests did not complete successfully.",
        error: {
          status: "Skipped",
          body: "The total successful requests bucket is required for this calculation."
        }
      }
    });
  }

  writeJsonLine(res, { type: "done" });
  res.end();
});

app.listen(port, host, () => {
  console.log(`Fastly NGWAF request dashboard running at http://${host}:${port}`);
});

module.exports = {
  app,
  buildPathFilter,
  buildQuery,
  getFastlyCount,
  normalizeDateForFastly
};
