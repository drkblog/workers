import { Router } from 'itty-router'

// Create a new router
const router = Router()

/*
Our index route, a simple hello world.
*/
router.get("/", () => {
  return new Response("Puzzle")
})

/*
This route demonstrates path parameters, allowing you to extract fragments from the request
URL.
Try visit /example/hello and see the response.

router.get("/example/:text", ({ params }) => {
  // Decode text like "Hello%20world" into "Hello world"
  let input = decodeURIComponent(params.text)

  // Construct a buffer from our input
  let buffer = Buffer.from(input, "utf8")

  // Serialise the buffer into a base64 string
  let base64 = buffer.toString("base64")

  // Return the HTML with the string to the client
  return new Response(`<p>Base64 encoding: <code>${base64}</code></p>`, {
    headers: {
      "Content-Type": "text/html"
    }
  })
})
*/

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
    console.log(RECAPTCHA_SECRET_KEY)
    let response = await fetch(`https://www.google.com/recaptcha/api/siteverify?secret=${RECAPTCHA_SECRET_KEY}&response=${token}&remoteip=${ip}`, {
        method: "POST",
    })
    let json = await response.json()

    if (json.success) {
      return false
    }

  } catch (err) {
    console.log("Fetch error", err)
    throw new Response("Oops! Something went wrong.", { status: 500 })
  }

  throw new Response("reCAPTCHA failed", { status: 400 })
}

async function readInput(request) {
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
    throw new Response("Invalid request!", { status: 400 })
  }

  const postData = await request.json()
  record["email"] = postData["email"]

  const recaptchaResult = testRecaptcha(postData["token"], record["ip"])
  if (recaptchaResult !== false) {
    return recaptchaResult
  }

  return record
}

/*
  Handler for /post
*/
router.post("/post", async request => {

  try {
    var record = await readInput(request)
  } catch(e) {
    return e
  }
  console.log(record)

  const hash = await createHash(record["email"], record["ip"])
  const recordString = JSON.stringify(record, null, 2)

  KV_PUZZLE.put(hash, recordString, {expirationTtl: 14400})

  return new Response(hash, {
    headers: {
      "Content-Type": "application/json"
    }
  })
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
  e.respondWith(router.handle(e.request))
})