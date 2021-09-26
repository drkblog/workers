import { Router } from 'itty-router'

const HTTP_OK = 200
const HTTP_BAD_REQUEST = 400
const HTTP_NOT_FOUND = 404
const HTTP_INTERNAL_SERVER_ERROR = 500

// Settings
const KV_PUZZLE_TTL = 14400

// Globals
const router = Router()

// Just fun
router.get("/", () => {
  return new Response("Puzzle")
})

function buf2hex(buffer) {
  return [...new Uint8Array(buffer)]
      .map(x => x.toString(16).padStart(2, '0'))
      .join('');
}

async function createHash(email, ip) {
  const now = new Date();
  const data = new TextEncoder().encode(email + ip + now.getMilliseconds().toString())

  const digest = await crypto.subtle.digest(
    {
      name: "SHA-256",
    },
    data,
  )
  return buf2hex(digest)
}

async function testRecaptcha(token, ip) {
  try {
    const body = `secret=${RECAPTCHA_SECRET_KEY}&response=${token}&remoteip=${ip}`
    console.log("reCAPTCHA fetch: " + body)
    const response = await fetch(
      'https://www.google.com/recaptcha/api/siteverify',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: body
      }
    )

    const json = await response.json()
    console.log("reCAPTCHA result: " + JSON.stringify(json))

    if (json.success) {
      console.log("reCAPTCHA validated")
      return true
    }

  } catch (err) {
    console.log("reCAPTCHA error", err)
    throw corsAwareResponse("Internal Server Error", HTTP_INTERNAL_SERVER_ERROR)
  }

  console.log("reCAPTCHA failed")
  throw corsAwareResponse("reCAPTCHA failed", HTTP_BAD_REQUEST)
}

async function readInput(request) {

  console.log("Entered readInput")

  const clientIP = request.headers.get("CF-Connecting-IP")

  let record = {
    "email": null,
    "answer": null,
    "ip": clientIP,
    "asn": null,
    "colo": null
  }

  // TODO: better handling of preview 
  if (request.cf) {
    record["asn"] = request.cf.asn
    record["colo"] = request.cf.colo
  }

  if (request.headers.get("Content-Type") !== "application/json") {
    console.log("Invalid content type")
    throw corsAwareResponse("Invalid content type", HTTP_BAD_REQUEST)
  }

  const postData = await request.json()
  record["email"] = postData["email"]
  record["answer"] = postData["answer"]

  await testRecaptcha(postData["g-recaptcha-response"], record["ip"])

  return record
}

async function sendmail(to, subject, body, from_email, from_name) {

  try {
    const mail_body = `secret=${SENDMAIL_SECRET_KEY}&to=${to}&subject=${subject}&body=${body}&from_email=${from_email}&from_name=${from_name}`

    console.log("mail to: " + to)
    const response = await fetch(
      SENDMAIL_SECRET_URL,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: mail_body
      }
    )
  } catch (err) {
    console.log("Sendmail error", err)
    throw corsAwareResponse("Internal Server Error", HTTP_INTERNAL_SERVER_ERROR)
  }
}

const originHeader = {
  "Access-Control-Allow-Origin": "https://www.drk.com.ar"
}
const corsHeaders = {
  ...originHeader,
  "Access-Control-Allow-Methods": "GET,HEAD,POST,OPTIONS",
  "Access-Control-Max-Age": "86400",
}

/*
  Handler for /post
*/
router.post("/post", async request => {

  console.log("Entered router.post")

  try {
    var record = await readInput(request)
  } catch(err) {
    console.log("Input validation failed: " + err)
    return err;
  }
  const hash = await createHash(record["email"], record["ip"])
  const recordString = JSON.stringify(record, null, 2)

  console.log(hash + " -> " + recordString)

  KV_PUZZLE.put(hash, recordString, {expirationTtl: KV_PUZZLE_TTL})

  const mail_body = `Validate your answer by following this link: ${new URL(request.url).origin}/validate/${hash}`
  sendmail(record["email"], 'Puzzle', mail_body, 'puzzle@drk.com.ar', 'drk.com.ar')

  return corsAwareResponse(hash)
})

function corsAwareResponse(body, status = HTTP_OK) {
  return new Response(body, {
    status: status,
    headers: {
      ...originHeader,
      "Content-Type": "application/json",
      "Vary": "Origin"
    }
  })
}

router.options("/post", async request => {
  // Add CORS headers
  let headers = request.headers;
  console.log(headers)
  if (
    headers.get("Origin") !== null &&
    headers.get("Access-Control-Request-Method") !== null &&
    headers.get("Access-Control-Request-Headers") !== null
  ) {
    let respHeaders = {
      ...corsHeaders,
      "Access-Control-Allow-Headers": request.headers.get("Access-Control-Request-Headers"),
    }

    return new Response(null, {
      headers: respHeaders,
    })
  }
  else {
    // Handle standard OPTIONS request
    return new Response(null, {
      headers: {
        Allow: "GET, HEAD, POST, OPTIONS",
      },
    })
  }
})

router.get("/validate/:hash", async ({ params }) => {
  return new Response(`Todo #${params.hash}`)
})

// Any route not matched before will return HTTP_NOT_FOUND
router.all("*", () => new Response("Not found", { status: HTTP_NOT_FOUND }))

addEventListener('fetch', (e) => {
  let response = router.handle(e.request)
  e.respondWith(response)
})