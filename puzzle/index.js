import { Router } from 'itty-router'

// Create a new router
const router = Router()

/*
Our index route, a simple hello world.
*/
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
    console.log("recaptcha fetch")
    let response = await fetch(
      `https://www.google.com/recaptcha/api/siteverify`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          secret: RECAPTCHA_SECRET_KEY,
          response: token
        })
      }
    )
    console.log("recaptcha json")
    let json = await response.json()

    console.log(JSON.stringify(json))

    if (json.success) {
      console.log("reCaptcha validated")
      return true
    }

  } catch (err) {
    console.log("Fetch error", err)
    throw new Response("Oops! Something went wrong.", { status: 500 })
  }

  console.log("reCAPTCHA failed")
  throw new Response("reCAPTCHA failed", { status: 400 })
}

async function readInput(request) {

  console.log("Entered readInput")

  const clientIP = request.headers.get("CF-Connecting-IP")

  let record = {
    "email": null,
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
    throw new Response("Invalid content type", { status: 400 })
  }

  const postData = await request.json()
  record["email"] = postData["email"]

  testRecaptcha(postData["g-recaptcha-response"], record["ip"])

  return record
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

  const record = await readInput(request)
  
  const hash = await createHash(record["email"], record["ip"])
  const recordString = JSON.stringify(record, null, 2)

  console.log(hash + " -> " + JSON.stringify(record, null, 2))

  KV_PUZZLE.put(hash, recordString, {expirationTtl: 14400})

  return new Response(hash, {
    headers: {
      ...originHeader,
      "Content-Type": "application/json",
      "Vary": "Origin"
    }
  })
})



router.options("/post", async request => {
  // Make sure the necessary headers are present
  // for this to be a valid pre-flight request
  let headers = request.headers;
  console.log(headers)
  if (
    headers.get("Origin") !== null &&
    headers.get("Access-Control-Request-Method") !== null &&
    headers.get("Access-Control-Request-Headers") !== null
  ){
    // Handle CORS pre-flight request.
    // If you want to check or reject the requested method + headers
    // you can do that here.
    let respHeaders = {
      ...corsHeaders,
    // Allow all future content Request headers to go back to browser
    // such as Authorization (Bearer) or X-Client-Name-Version
      "Access-Control-Allow-Headers": request.headers.get("Access-Control-Request-Headers"),
    }

    return new Response(null, {
      headers: respHeaders,
    })
  }
  else {
    // Handle standard OPTIONS request.
    // If you want to allow other HTTP Methods, you can do that here.
    return new Response(null, {
      headers: {
        Allow: "GET, HEAD, POST, OPTIONS",
      },
    })
  }
})

/*
This is the last route we define, it will match anything that hasn't hit a route we've defined
above, therefore it's useful as a 404 (and avoids us hitting worker exceptions, so make sure to include it!).
Visit any page that doesn't exist (e.g. /foobar) to see it in action.
*/
router.all("*", () => new Response("404, not found!", { status: 404 }))

/*
This snippet ties our worker to the router we deifned above, all incoming requests
are passed to the router where your routes are called and the response is sent.
*/
addEventListener('fetch', (e) => {
  let response = router.handle(e.request)
  e.respondWith(response)
})