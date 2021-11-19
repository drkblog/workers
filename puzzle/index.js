import { Router } from 'itty-router';

const HTTP_OK = 200;
const HTTP_SEE_OTHER = 303
const HTTP_BAD_REQUEST = 400;
const HTTP_NOT_FOUND = 404;
const HTTP_CONFLICT = 409;
const HTTP_INTERNAL_SERVER_ERROR = 500;

const REPLY_EMAIL_VALIDATED_ANSWER_INCORRECT = 1;
const REPLY_EMAIL_VALIDATED_ANSWER_CORRECT = 2;

const FROM_EMAIL_ADDRESS = 'puzzle@drk.com.ar';
const FROM_DISPLAY_NAME = 'drkbugs';
const EMAIL_SUBJECT = '#drkquest1';

const hash_validation_regex = /[0-9a-f]{64}/;

const BASE_RECORD = {
  "email": null,
  "answer": null,
  "answer_date": null,
  "ip": null,
  "asn": null,
  "colo": null,
  "verification": null
};

const VERIFICATION_RECORD = {
  "verified": false,
  "verification_date": null,
  "verification_ip": null,
  "answer_is_correct": false
};

// Settings
const KV_PUZZLE_TTL = 12 * 60 * 60;

// Globals
const router = Router();

// Just fun
router.get("/", () => {
  return new Response("drkbugs");
});

function buf2hex(buffer) {
  return [...new Uint8Array(buffer)]
      .map(x => x.toString(16).padStart(2, '0'))
      .join('');
}

async function createHash(email, ip) {
  const now = new Date();
  const data = new TextEncoder().encode(email + ip + now.getMilliseconds().toString());

  const digestBuffer = await crypto.subtle.digest(
    {
      name: "SHA-256",
    },
    data,
  );
  return buf2hex(digestBuffer);
}

async function answerIsCorrect(answer) {
  const data =  new TextEncoder().encode(answer);
  const digestBuffer = await crypto.subtle.digest(
    {
      name: "SHA-512",
    },
    data,
  );
  const digest = buf2hex(digestBuffer);

  console.log({answer, data, digest});

  return digest === PUZZLE_SECRET_ANSWER;
}

async function testRecaptcha(token, ip) {
  try {
    const body = `secret=${RECAPTCHA_SECRET_KEY}&response=${token}&remoteip=${ip}`;
    console.log("reCAPTCHA fetch: " + body);
    const response = await fetch(
      'https://www.google.com/recaptcha/api/siteverify',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: body
      }
    );

    const json = await response.json();
    console.log("reCAPTCHA result: " + JSON.stringify(json));

    if (json.success) {
      console.log("reCAPTCHA validated");
      return true;
    }

  } catch (err) {
    console.log("reCAPTCHA error", err);
    throw corsAwareResponse("Internal Server Error", HTTP_INTERNAL_SERVER_ERROR);
  }

  console.log("reCAPTCHA failed");
  throw corsAwareResponse("reCAPTCHA failed", HTTP_BAD_REQUEST);
}

async function readInput(request) {

  console.log("Entered readInput");

  const clientIP = request.headers.get("CF-Connecting-IP");

  let record = BASE_RECORD;
  record.ip = clientIP;

  // TODO: better handling of preview 
  if (request.cf) {
    record.asn = request.cf.asn;
    record.colo = request.cf.colo;
  }

  if (request.headers.get("Content-Type") !== "application/json") {
    console.log("Invalid content type");
    throw corsAwareResponse("Invalid content type", HTTP_BAD_REQUEST);
  }

  const postData = await request.json();
  record.email = postData["email"];
  record.answer = postData["answer"];
  record.answer_date = new Date();

  await testRecaptcha(postData["g-recaptcha-response"], record.ip);

  return record;
}

async function sendmail(to, subject, body, from_email, from_name) {

  try {
    const mail_body = `secret=${SENDMAIL_SECRET_KEY}&to=${to}&subject=${subject}&body=${body}&from_email=${from_email}&from_name=${from_name}`;

    console.log("mail to: " + to);
    const response = await fetch(
      SENDMAIL_SECRET_URL,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: mail_body
      }
    );
  } catch (err) {
    console.log("Sendmail error", err);
    throw corsAwareResponse("Internal Server Error", HTTP_INTERNAL_SERVER_ERROR);
  }
}

const originHeader = {
  "Access-Control-Allow-Origin": "https://www.drk.com.ar"
};
const corsHeaders = {
  ...originHeader,
  "Access-Control-Allow-Methods": "GET,HEAD,POST,OPTIONS",
  "Access-Control-Max-Age": "86400",
};

/*
  Handler for /post
*/
router.post("/post", async request => {

  console.log("Entered router.post");

  try {
    var record = await readInput(request);
  } catch(err) {
    console.log("Input validation failed: " + err);
    return err;
  }
  const hash = await createHash(record["email"], record["ip"]);
  const recordString = JSON.stringify(record, null, 2);

  console.log(hash + " -> " + recordString);

  await KV_PUZZLE.put(hash, recordString, {expirationTtl: KV_PUZZLE_TTL});

  const link_duration = KV_PUZZLE_TTL / 3600;
  const mail_body = `
      Validá tu dirección de correo y tu respuesta entrando al siguiente enlace: ${new URL(request.url).origin}/verify/${hash}\n
      Este enlace dura ${link_duration} horas y no funcionará pasado ese tiempo.
  `;

  sendmail(record["email"], EMAIL_SUBJECT, mail_body, FROM_EMAIL_ADDRESS, FROM_DISPLAY_NAME);

  return corsAwareResponse('Respuesta aceptada. Recibirás un correo electrónico para validar tu dirección y la respuesta.');
})

function corsAwareResponse(body, status = HTTP_OK) {
  return new Response(body, {
    status: status,
    headers: {
      ...originHeader,
      "Content-Type": "application/json",
      "Vary": "Origin"
    }
  });
}

function corsAwareRedirectResponse(message, getString = null, redirectCode = HTTP_SEE_OTHER) {
  const destinationURL = `https://drk.com.ar/drkquest1-reply-${message}/` + ((getString != null) ? `?${getString}` : '');
  return Response.redirect(destinationURL, redirectCode);
}

router.options("/post", async request => {
  // Add CORS headers
  let headers = request.headers;
  console.log(headers);
  if (
    headers.get("Origin") !== null &&
    headers.get("Access-Control-Request-Method") !== null &&
    headers.get("Access-Control-Request-Headers") !== null
  ) {
    let respHeaders = {
      ...corsHeaders,
      "Access-Control-Allow-Headers": request.headers.get("Access-Control-Request-Headers"),
    };

    return new Response(null, {
      headers: respHeaders,
    });
  }
  else {
    // Handle standard OPTIONS request
    return new Response(null, {
      headers: {
        Allow: "GET, HEAD, POST, OPTIONS",
      },
    });
  }
})

router.get("/verify/:hash", async (request) => {
  const { params, query } = request;
  const hash = params.hash;

  if (!hash.match(hash_validation_regex)) {
    return corsAwareResponse("Invalid hash format", HTTP_BAD_REQUEST);
  }

  const clientIP = request.headers.get("CF-Connecting-IP");

  const record = await KV_PUZZLE.get(hash, {type: "json"});
  if (record === null) {
    return corsAwareResponse("Invalid hash", HTTP_NOT_FOUND);
  }

  if (record.verification !== null) {
    return corsAwareResponse('Esta respuesta y dirección de correo ya fueron validadas anteriormente.', HTTP_CONFLICT);
  }

  const isCorrect = await answerIsCorrect(record.answer);

  const verification_record = VERIFICATION_RECORD;
  verification_record.verified = true;
  verification_record.verification_ip = clientIP;
  verification_record.verification_date = new Date();
  verification_record.answer_is_correct = isCorrect;
  record.verification = verification_record;

  const recordString = JSON.stringify(record, null, 2);
  console.log(hash + " -> " + recordString);

  await KV_PUZZLE.put(hash, recordString);

  if (isCorrect === true) {
    return new corsAwareRedirectResponse(REPLY_EMAIL_VALIDATED_ANSWER_CORRECT, hash);
  } else {
    return new corsAwareRedirectResponse(REPLY_EMAIL_VALIDATED_ANSWER_INCORRECT);
  }
})

// Any route not matched before will return HTTP_NOT_FOUND
router.all("*", () => new Response("Not found", { status: HTTP_NOT_FOUND }));

addEventListener('fetch', (e) => {
  let response = router.handle(e.request);
  e.respondWith(response);
});