import { Router } from 'itty-router';

const HTTP_OK = 200;
const HTTP_SEE_OTHER = 303
const HTTP_BAD_REQUEST = 400;
const HTTP_NOT_FOUND = 404;
const HTTP_CONFLICT = 409;
const HTTP_TOO_MANY_REQUESTS = 429;
const HTTP_INTERNAL_SERVER_ERROR = 500;

const FROM_EMAIL_ADDRESS = 'webmaster@drk.com.ar';
const FROM_DISPLAY_NAME = '@drkbugs';
const EMAIL_SUBJECT = 'Confirmá inscripción en drkbugs - festejo 10.000 seguidores';

const hash_validation_regex = /[0-9a-f]{64}/;

const BASE_RECORD = {
  'email': null,
  'tiktok_username': null,
  'signup_date': null,
  'ip': null,
  'asn': null,
  'colo': null,
  'verification': null
};

const VERIFICATION_RECORD = {
  'verified': false,
  'verification_date': null,
  'verification_ip': null
};

// Settings
const KV_SIGNUP_TTL = 12 * 60 * 60;
const KV_SIGNUP_THROTTLE_TTL = 60;

// Globals
const router = Router();

// Just fun
router.get('/', () => {
  return new Response('drkbugs');
});

function generateRandomHash(size) {
  const randomBytes = new Uint8Array(size);
  crypto.getRandomValues(randomBytes);
  return [...randomBytes].map(x => x.toString(16).padStart(2, '0')).join('');
}

async function testRecaptcha(token, ip) {
  try {
    const body = `secret=${RECAPTCHA_SECRET_KEY}&response=${token}&remoteip=${ip}`;
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

    if (json.success) {
      return true;
    }

  } catch (err) {
    console.error(`reCAPTCHA error: ${err}`);
    throw corsAwareResponse('Internal Server Error', HTTP_INTERNAL_SERVER_ERROR);
  }

  throw corsAwareResponse('reCAPTCHA failed', HTTP_BAD_REQUEST);
}

async function throttle(ip) {
  const present = await KV_SIGNUP_THROTTLE.get(ip);

  if (present != null) {
    const message = `Sólo se puede enviar una respuesta cada ${KV_SIGNUP_THROTTLE_TTL} segundos desde una dirección IP`;
    throw corsAwareResponse(message, HTTP_TOO_MANY_REQUESTS);
  }

  await KV_SIGNUP_THROTTLE.put(ip, 'true', { expirationTtl: KV_SIGNUP_THROTTLE_TTL });
}

async function processAnswerData(request) {

  const clientIP = request.headers.get('CF-Connecting-IP');

  await throttle(clientIP);

  var record = BASE_RECORD;
  record.ip = clientIP;

  // TODO: better handling of preview 
  if (request.cf) {
    record.asn = request.cf.asn;
    record.colo = request.cf.colo;
  }

  if (request.headers.get('Content-Type') !== 'application/json') {
    console.error('Invalid content type');
    throw corsAwareResponse('Invalid content type', HTTP_BAD_REQUEST);
  }

  const postData = await request.json();
  record.email = postData['email'];
  record.tiktok_username = postData['tiktok_username'];
  record.signup_date = new Date();

  await testRecaptcha(postData['g-recaptcha-response'], record.ip);

  return record;
}

async function sendmail(to, subject, body, from_email, from_name) {

  try {
    const mail_body = `secret=${SENDMAIL_SECRET_KEY}&to=${to}&subject=${subject}&body=${body}&from_email=${from_email}&from_name=${from_name}`;
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
    console.debug(response);
  } catch (err) {
    console.error(`Sendmail error: ${err}`);
    throw corsAwareResponse('Internal Server Error', HTTP_INTERNAL_SERVER_ERROR);
  }
}

const originHeader = {
  'Access-Control-Allow-Origin': 'https://www.drk.com.ar'
};
const corsHeaders = {
  ...originHeader,
  'Access-Control-Allow-Methods': 'GET,HEAD,POST,OPTIONS',
  'Access-Control-Max-Age': '86400',
};

/*
  Handler for /post
*/
router.post('/post', async request => {

  try {
    var record = await processAnswerData(request);
  } catch(err) {
    console.error(`Input validation/sanitization failed: ${err}`);
    return err;
  }
  const hash = generateRandomHash(30);
  const recordString = JSON.stringify(record, null, 2);

  await KV_SIGNUP.put(hash, recordString, { expirationTtl: KV_SIGNUP_TTL });

  const link_duration = KV_SIGNUP_TTL / 3600;
  const mail_body = `
      <h3>¡Festejamos los 10.000 seguidores de mi cuenta de TikTok!</h3>\n
      <p>
        <strong>Gracias por participar y apoyar.</strong> Si aún no lo hiciste te recomiendo que me sigas en Instagram y en YouTube.<br>\n
        Validá tu dirección de correo entrando al siguiente enlace: ${new URL(request.url).origin}/verify/${hash}<br>\n
        Este enlace dura ${link_duration} horas y no funcionará pasado ese tiempo.
      </p>
      <p>
        Estás recibiendo este correo porque completaste el formulario en <a href="https://drk.com.ar/10k">https://drk.com.ar/10k</a>.
        Si no lo hiciste ignorá este corre por completo.
      </p>
  `;

  await sendmail(record['email'], EMAIL_SUBJECT, mail_body, FROM_EMAIL_ADDRESS, FROM_DISPLAY_NAME);

  return corsAwareResponse('<strong>Inscripción iniciada.</strong> Recibirás un correo electrónico para <strong>validar tu dirección</strong>.<br>Revisá tu casilla de spam si no recibís el mensaje en tu casilla de entrada en 15 minutos.');
})

function corsAwareResponse(body, status = HTTP_OK) {
  return new Response(body, {
    status: status,
    headers: {
      ...originHeader,
      'Content-Type': 'application/json',
      'Vary': 'Origin'
    }
  });
}

function corsAwareRedirectResponseOk(redirectCode = HTTP_SEE_OTHER) {
  const destinationURL = 'https://drk.com.ar/10k-ok/';
  return Response.redirect(destinationURL, redirectCode);
}

router.options('/post', async request => {
  // Add CORS headers
  const headers = request.headers;
  if (
    headers.get('Origin') !== null &&
    headers.get('Access-Control-Request-Method') !== null &&
    headers.get('Access-Control-Request-Headers') !== null
  ) {
    const respHeaders = {
      ...corsHeaders,
      'Access-Control-Allow-Headers': request.headers.get('Access-Control-Request-Headers'),
    };

    return new Response(null, {
      headers: respHeaders,
    });
  }
  else {
    // Handle standard OPTIONS request
    return new Response(null, {
      headers: {
        Allow: 'GET, HEAD, POST, OPTIONS',
      },
    });
  }
})

router.get('/verify/:hash', async (request) => {
  const { params, query } = request;
  const hash = params.hash;

  if (!hash.match(hash_validation_regex)) {
    return corsAwareResponse('Invalid hash format', HTTP_BAD_REQUEST);
  }

  const clientIP = request.headers.get('CF-Connecting-IP');

  const record = await KV_SIGNUP.get(hash, { type: 'json' });
  if (record === null) {
    return corsAwareResponse('Invalid hash', HTTP_NOT_FOUND);
  }

  if (record.verification !== null) {
    return corsAwareResponse('Esta dirección de correo ya fue validada anteriormente.', HTTP_CONFLICT);
  }

  const verification_record = VERIFICATION_RECORD;
  verification_record.verified = true;
  verification_record.verification_ip = clientIP;
  verification_record.verification_date = new Date();
  record.verification = verification_record;

  const recordString = JSON.stringify(record, null, 2);

  await KV_SIGNUP.put(hash, recordString);

  return new corsAwareRedirectResponseOk();
})

// Any route not matched before will return HTTP_NOT_FOUND
router.all('*', () => new Response('Not found', { status: HTTP_NOT_FOUND }));

addEventListener('fetch', (e) => {
  let response = router.handle(e.request);
  e.respondWith(response);
});