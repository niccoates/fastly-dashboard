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
const maxSelectedRangeDays = 30;
const maxFastlyChunkDays = 7;
const collectionResults = new Map();

const buckets = [
  {
    name: "Total successful requests",
    collectionKey: "total",
    template: "server:{server} {paths} from:{from} until:{until} httpcode:200",
    total: true
  },
  {
    name: "Human visitors - strict candidates",
    collectionKey: "human",
    template:
      'server:{server} {paths} from:{from} until:{until} httpcode:200 requestheader:Sec-Fetch-User:"?1" -tag:SUSPECTED-BOT -tag:SUSPECTED-BAD-BOT -tag:DATACENTER sort:time-desc',
    positive: true
  },
  {
    name: "LLM / AI crawler and fetcher samples",
    collectionKey: "llms",
    template:
      "server:{server} {paths} from:{from} until:{until} httpcode:200 tag:VERIFIED-BOT.AI-FETCHER tag:VERIFIED-BOT.AI-CRAWLER tag:SUSPECTED-BOT.AI-FETCHER tag:SUSPECTED-BOT.AI-CRAWLER sort:time-desc",
    positive: true
  },
  {
    name: "Status aggregators",
    collectionKey: "statusAggregators",
    template:
      "server:{server} {paths} from:{from} until:{until} httpcode:200 useragent:~StatusGator useragent:~PulseBoard useragent:~ReliabilityAPI useragent:~VendorMonitor useragent:~StatusMonitor sort:time-desc",
    positive: true
  },
  {
    name: "Synthetic monitoring samples",
    collectionKey: "syntheticMonitoring",
    template:
      "server:{server} {paths} from:{from} until:{until} httpcode:200 useragent:~Catchpoint useragent:~uptime-monitor useragent:~UptimeRobot useragent:~Pingdom useragent:~StatusCake useragent:~Datadog useragent:~Site24x7 useragent:~Checkly useragent:~Uptrends useragent:~BetterStack sort:time-desc",
    positive: true
  },
  {
    name: "Known search crawlers",
    collectionKey: "searchCrawlers",
    template:
      "server:{server} {paths} from:{from} until:{until} httpcode:200 tag:VERIFIED-BOT.SEARCH-ENGINE-CRAWLER sort:time-desc",
    positive: true
  },
  {
    name: "Enterprise automation / customer polling samples",
    collectionKey: "enterpriseAutomation",
    template:
      'server:{server} {paths} from:{from} until:{until} httpcode:200 useragent:"Splunk (Default)" useragent:~PowerShell useragent:~curl useragent:~python useragent:~Go-http-client useragent:~Java useragent:~Wget sort:time-desc',
    positive: true
  },
  {
    name: "Bad bot / scanner / impersonator",
    collectionKey: "badBots",
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

function normalizeServerInput(server) {
  const value = String(server || "").trim();

  if (!value) {
    return "";
  }

  try {
    return new URL(value.includes("://") ? value : `https://${value}`).hostname;
  } catch (_error) {
    return value;
  }
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

function parseDateInput(dateValue) {
  const value = String(dateValue || "");

  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    return null;
  }

  const [year, month, day] = value.split("-").map(Number);
  const date = new Date(Date.UTC(year, month - 1, day));

  if (
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day
  ) {
    return null;
  }

  return date;
}

function formatDateInput(date) {
  return date.toISOString().slice(0, 10);
}

function addUtcDays(date, days) {
  const nextDate = new Date(date);
  nextDate.setUTCDate(nextDate.getUTCDate() + days);
  return nextDate;
}

function utcStartOfDay(date = new Date()) {
  return new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
}

function lastThirtyDayRange(today = new Date()) {
  const untilDate = utcStartOfDay(today);
  const fromDate = addUtcDays(untilDate, -maxSelectedRangeDays);
  const displayUntilDate = addUtcDays(untilDate, -1);

  return {
    from: formatDateInput(fromDate),
    until: formatDateInput(untilDate),
    displayUntil: formatDateInput(displayUntilDate)
  };
}

function buildDateChunks(fromValue, untilValue) {
  const fromDate = parseDateInput(fromValue);
  const untilDate = parseDateInput(untilValue);

  if (!fromDate || !untilDate || fromDate >= untilDate) {
    return [];
  }

  const chunks = [];
  let chunkFrom = fromDate;

  while (chunkFrom < untilDate) {
    const chunkUntil = new Date(
      Math.min(addUtcDays(chunkFrom, maxFastlyChunkDays).getTime(), untilDate.getTime())
    );

    chunks.push({
      from: formatDateInput(chunkFrom),
      until: formatDateInput(chunkUntil),
      label: `${formatDateInput(chunkFrom)} to ${formatDateInput(chunkUntil)} (until exclusive)`
    });

    chunkFrom = chunkUntil;
  }

  return chunks;
}

function buildPathFilter(pathsInput) {
  return String(pathsInput || "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((pathValue) => `path:${pathValue}`)
    .join(" ");
}

function decodeXmlText(value) {
  return String(value || "")
    .replaceAll("&amp;", "&")
    .replaceAll("&lt;", "<")
    .replaceAll("&gt;", ">")
    .replaceAll("&quot;", '"')
    .replaceAll("&apos;", "'");
}

function extractSitemapLocs(xml) {
  return Array.from(String(xml || "").matchAll(/<loc>\s*(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?\s*<\/loc>/gi))
    .map((match) => decodeXmlText(match[1]).trim())
    .filter(Boolean);
}

function serviceLandingVariants(pathname) {
  let pathValue = String(pathname || "");

  if (!pathValue.startsWith("/")) {
    pathValue = `/${pathValue}`;
  }

  if (!/^\/services\/[^/]+\/?$/.test(pathValue)) {
    return [];
  }

  const withoutTrailingSlash = pathValue.replace(/\/$/, "");
  return [withoutTrailingSlash, `${withoutTrailingSlash}/`];
}

function collectionPagesFromSitemap(xml, server) {
  const pages = new Map();

  extractSitemapLocs(xml).forEach((loc) => {
    let variants = [];

    try {
      const url = new URL(loc);

      if (normalizeServerInput(url.hostname) !== normalizeServerInput(server)) {
        return;
      }

      variants = serviceLandingVariants(url.pathname);
    } catch (_error) {
      variants = serviceLandingVariants(loc);
    }

    if (variants.length === 0) {
      return;
    }

    const canonicalPath = variants[0];
    pages.set(canonicalPath, {
      path: canonicalPath,
      variants
    });
  });

  return Array.from(pages.values()).sort((left, right) => left.path.localeCompare(right.path));
}

async function fetchCollectionPaths(server) {
  const normalizedServer = normalizeServerInput(server);
  const sitemapUrl = new URL(`https://${normalizedServer}/sitemap.xml`);
  const response = await fetch(sitemapUrl, {
    method: "GET",
    headers: {
      Accept: "application/xml,text/xml;q=0.9,*/*;q=0.8"
    }
  });
  const body = await response.text();

  if (!response.ok) {
    const error = new Error(`Sitemap request failed with status ${response.status}`);
    error.status = response.status;
    error.body = body;
    error.sitemapUrl = sitemapUrl.toString();
    throw error;
  }

  return {
    sitemapUrl: sitemapUrl.toString(),
    pages: collectionPagesFromSitemap(body, normalizedServer)
  };
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

function buildChunkQuery(template, form, chunk) {
  return buildQuery(template, {
    ...form,
    from: chunk.from,
    until: chunk.until
  });
}

async function getBucketCountAcrossChunks({ workspaceId, token, bucket, form, chunks }) {
  let total = 0;
  const queries = [];

  for (const chunk of chunks) {
    const query = buildChunkQuery(bucket.template, form, chunk);
    const count = await getFastlyCountWithRetry({
      workspaceId,
      token,
      query
    });

    total += count;
    queries.push(query);

    if (chunk !== chunks[chunks.length - 1] && requestDelayMs > 0) {
      await delay(requestDelayMs);
    }
  }

  return { total, queries };
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
  const range = lastThirtyDayRange();

  return {
    server: "status.broadcom.com",
    paths: "",
    collection: false,
    from: range.from,
    until: range.until,
    displayUntil: range.displayUntil
  };
}

function validateForm(form) {
  const errors = [];

  if (!FASTLY_API_KEY) errors.push("FASTLY_API_KEY is not set.");
  if (!FASTLY_WORKSPACE_ID) errors.push("FASTLY_WORKSPACE_ID is not set.");
  if (!form.server.trim()) errors.push("Server hostname is required.");

  return errors;
}

function buildRunForm(body) {
  const range = lastThirtyDayRange();
  const collection = Boolean(body.collection);

  return {
    server: normalizeServerInput(body.server),
    paths: collection ? "" : body.paths || "",
    collection,
    from: range.from,
    until: range.until,
    displayUntil: range.displayUntil
  };
}

function percentageOfTotal(total, totalSuccessful) {
  if (typeof total !== "number" || typeof totalSuccessful !== "number" || totalSuccessful <= 0) {
    return null;
  }

  return (total / totalSuccessful) * 100;
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
  const form = buildRunForm(req.body);
  const errors = validateForm(form);
  const chunks = buildDateChunks(form.from, form.until);
  const results = [];
  let apiError = null;
  let totalSuccessful;

  if (errors.length === 0) {
    for (const bucket of buckets) {
      try {
        const query = buildQuery(bucket.template, form);
        const { total, queries } = await getBucketCountAcrossChunks({
          workspaceId: FASTLY_WORKSPACE_ID,
          token: FASTLY_API_KEY,
          bucket,
          form,
          chunks
        });

        results.push({
          name: bucket.name,
          query,
          queries,
          chunks,
          total,
          positive: bucket.positive,
          totalBucket: bucket.total
        });

        if (bucket.total) {
          totalSuccessful = total;
        }

        if (bucket !== buckets[buckets.length - 1] && requestDelayMs > 0) {
          await delay(requestDelayMs);
        }
      } catch (error) {
        const query = error.query || buildQuery(bucket.template, form);
        results.push({
          name: bucket.name,
          query,
          chunks,
          error: {
            status: error.status || "Unknown",
            body: error.body || error.message
          }
        });
      }
    }

    totalSuccessful = results.find((result) => result.totalBucket)?.total;
    results.forEach((result) => {
      if (!result.error) {
        result.percentageOfTotal = percentageOfTotal(result.total, totalSuccessful);
      }
    });

    const positivelyIdentifiedTotal = results
      .filter((result) => result.positive && typeof result.total === "number")
      .reduce((sum, result) => sum + result.total, 0);

    if (typeof totalSuccessful === "number") {
      const otherTotal = Math.max(0, totalSuccessful - positivelyIdentifiedTotal);
      results.push({
        name: "Other automated / suspicious / unknown",
        query: "Not queried. Calculated locally as total successful requests minus identified buckets.",
        total: otherTotal,
        percentageOfTotal: percentageOfTotal(otherTotal, totalSuccessful),
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

function collectionProgressPayload({ current, total, label }) {
  return {
    type: "collection-progress",
    current,
    total,
    percent: total > 0 ? Math.round((current / total) * 100) : 0,
    label
  };
}

function collectionJsonFileName(server) {
  const dateValue = new Date().toISOString().slice(0, 10);
  return `${normalizeServerInput(server).replace(/[^a-z0-9.-]+/gi, "-")}-collection-${dateValue}.json`;
}

function formatPercentageValue(value) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) {
    return null;
  }

  return `${Number(value).toFixed(2)}%`;
}

function addCollectionPercentages(pathResults) {
  const totalSuccessful = pathResults?.total?.total;

  Object.values(pathResults || {}).forEach((bucketResult) => {
    if (bucketResult && typeof bucketResult.total === "number") {
      bucketResult.percentage = formatPercentageValue(percentageOfTotal(bucketResult.total, totalSuccessful));
    }
  });
}

async function runCollectionMode({ res, form, chunks }) {
  writeJsonLine(res, collectionProgressPayload({
    current: 0,
    total: 1,
    label: `Fetching https://${form.server}/sitemap.xml`
  }));

  const { sitemapUrl, pages: collectionPages } = await fetchCollectionPaths(form.server);

  if (collectionPages.length === 0) {
    writeJsonLine(res, {
      type: "api-error",
      result: {
        name: "Collection sitemap",
        query: sitemapUrl,
        error: {
          status: "No paths",
          body: "No top-level /services/{service_name} paths were found in sitemap.xml."
        }
      }
    });
    return;
  }

  const totalSteps = collectionPages.length * buckets.length;
  let completedSteps = 0;
  const pages = {};

  writeJsonLine(res, {
    type: "collection-started",
    pathCount: collectionPages.length,
    bucketCount: buckets.length,
    totalSteps,
    sitemapUrl
  });

  for (const page of collectionPages) {
    pages[page.path] = {};
    let totalSuccessful;

    for (const bucket of buckets) {
      const label = `${page.path} - ${bucket.collectionKey}`;
      writeJsonLine(res, collectionProgressPayload({
        current: completedSteps,
        total: totalSteps,
        label
      }));

      try {
        const bucketForm = {
          ...form,
          paths: page.variants.join("\n")
        };
        const { total } = await getBucketCountAcrossChunks({
          workspaceId: FASTLY_WORKSPACE_ID,
          token: FASTLY_API_KEY,
          bucket,
          form: bucketForm,
          chunks
        });

        if (bucket.total) {
          totalSuccessful = total;
        }

        pages[page.path][bucket.collectionKey] = {
          total,
          percentage: formatPercentageValue(percentageOfTotal(total, totalSuccessful))
        };
      } catch (error) {
        pages[page.path][bucket.collectionKey] = {
          error: {
            status: error.status || "Unknown",
            body: error.body || error.message
          }
        };
      }

      completedSteps += 1;
      writeJsonLine(res, collectionProgressPayload({
        current: completedSteps,
        total: totalSteps,
        label
      }));

      if (completedSteps < totalSteps && requestDelayMs > 0) {
        await delay(requestDelayMs);
      }
    }

    addCollectionPercentages(pages[page.path]);
  }

  const output = {
    generatedAt: new Date().toISOString(),
    server: form.server,
    range: {
      from: form.from,
      through: form.displayUntil,
      untilExclusive: form.until
    },
    pages
  };
  const id = crypto.randomUUID();

  collectionResults.set(id, {
    filename: collectionJsonFileName(form.server),
    output
  });

  writeJsonLine(res, {
    type: "collection-complete",
    downloadUrl: `/collection-results/${id}`,
    pathCount: collectionPages.length
  });
}

app.get("/collection-results/:id", (req, res) => {
  const result = collectionResults.get(req.params.id);

  if (!result) {
    res.status(404).send("Collection result not found");
    return;
  }

  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="${result.filename}"`);
  res.send(JSON.stringify(result.output, null, 2));
});

app.post("/run", async (req, res) => {
  const form = buildRunForm(req.body);
  const errors = validateForm(form);
  const chunks = buildDateChunks(form.from, form.until);

  res.setHeader("Content-Type", "application/x-ndjson; charset=utf-8");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("X-Accel-Buffering", "no");

  if (errors.length > 0) {
    writeJsonLine(res, { type: "validation-error", errors });
    res.end();
    return;
  }

  if (form.collection) {
    try {
      await runCollectionMode({ res, form, chunks });
    } catch (error) {
      writeJsonLine(res, {
        type: "api-error",
        result: {
          name: "Collection run",
          query: error.sitemapUrl || `https://${form.server}/sitemap.xml`,
          error: {
            status: error.status || "Unknown",
            body: error.body || error.message
          }
        }
      });
    }

    writeJsonLine(res, { type: "done" });
    res.end();
    return;
  }

  const results = [];
  let totalSuccessful;

  for (const bucket of buckets) {
    const query = buildQuery(bucket.template, form);
    writeJsonLine(res, {
      type: "started",
      name: bucket.name,
      query,
      chunks
    });

    try {
      const { total, queries } = await getBucketCountAcrossChunks({
        workspaceId: FASTLY_WORKSPACE_ID,
        token: FASTLY_API_KEY,
        bucket,
        form,
        chunks
      });
      const result = {
        name: bucket.name,
        query,
        queries,
        chunks,
        total,
        positive: bucket.positive,
        totalBucket: bucket.total,
        percentageOfTotal: percentageOfTotal(total, totalSuccessful)
      };

      if (bucket.total) {
        totalSuccessful = total;
        result.percentageOfTotal = percentageOfTotal(total, totalSuccessful);
      }

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
          chunks,
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

  totalSuccessful = results.find((result) => result.totalBucket)?.total;
  const positivelyIdentifiedTotal = results
    .filter((result) => result.positive && typeof result.total === "number")
    .reduce((sum, result) => sum + result.total, 0);

  if (typeof totalSuccessful === "number") {
    const otherTotal = Math.max(0, totalSuccessful - positivelyIdentifiedTotal);
    writeJsonLine(res, {
      type: "result",
      result: {
        name: "Other automated / suspicious / unknown",
        query: "Not queried. Calculated locally as total successful requests minus identified buckets.",
        total: otherTotal,
        percentageOfTotal: percentageOfTotal(otherTotal, totalSuccessful),
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

if (require.main === module) {
  app.listen(port, host, () => {
    console.log(`Fastly NGWAF request dashboard running at http://${host}:${port}`);
  });
}

module.exports = {
  app,
  addCollectionPercentages,
  buildDateChunks,
  buildPathFilter,
  buildQuery,
  collectionPagesFromSitemap,
  lastThirtyDayRange,
  getFastlyCount,
  normalizeDateForFastly
};
