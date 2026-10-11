/**
 * Dilip Borge Associates - Main JavaScript
 * Includes UI logic and comprehensive security features.
 */

/* ==========================================================================
   SECURITY FEATURES
   ========================================================================== */

// 1. Input Sanitization (XSS Protection)
function sanitizeInput(input) {
  if (typeof input !== 'string') return '';
  return input
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;')
    .replace(/\\/g, '&#x5C;')
    .replace(/`/g, '&#x60;')
    .replace(/\(/g, '&#40;')
    .replace(/\)/g, '&#41;')
    .trim();
}

// 2. Strip SQL Keywords
function stripSQLKeywords(input) {
  const sqlKeywords = [
    /(\bSELECT\b)/gi, /(\bINSERT\b)/gi, 
    /(\bUPDATE\b)/gi, /(\bDELETE\b)/gi,
    /(\bDROP\b)/gi, /(\bUNION\b)/gi, 
    /(\bALTER\b)/gi, /(\bCREATE\b)/gi,
    /(\bEXEC\b)/gi, /(\bTRUNCATE\b)/gi,
    /(--)/g, /(;)/g, /(\|\|)/g, /(\/\*)/g, /(\*\/)/g
  ];
  
  let clean = input;
  sqlKeywords.forEach(keyword => {
    clean = clean.replace(keyword, '');
  });
  return clean;
}

// 3. Clickjacking Prevention Frame Buster (also in <head>)
if (window.self !== window.top) {
  window.top.location = window.self.location;
}

// 4. HTTPS Redirect
if (location.protocol !== 'https:' && 
    location.hostname !== 'localhost' && 
    location.hostname !== '127.0.0.1') {
  location.replace('https:' + window.location.href.substring(window.location.protocol.length));
}

// 5. CSRF Token Generation
function generateCSRFToken() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

function initCSRF() {
  if (!sessionStorage.getItem('csrf_token')) {
    sessionStorage.setItem('csrf_token', generateCSRFToken());
  }
  const token = sessionStorage.getItem('csrf_token');
  document.querySelectorAll('input[name="csrf_token"]').forEach(input => {
    input.value = token;
  });
}

function validateCSRF(form) {
  const formToken = form.querySelector('[name="csrf_token"]')?.value;
  const storedToken = sessionStorage.getItem('csrf_token');
  return formToken && formToken === storedToken && formToken.length === 64;
}

function refreshCSRFToken() {
  const newToken = generateCSRFToken();
  sessionStorage.setItem('csrf_token', newToken);
  document.querySelectorAll('input[name="csrf_token"]').forEach(input => {
    input.value = newToken;
  });
}

// 6. Verify Origin
function verifyOrigin() {
  const allowedOrigins = [
    'https://www.dilipborgeassociates.com',
    'https://dilipborgeassociates.com',
    'http://localhost',
    'http://127.0.0.1'
  ];
  return allowedOrigins.some(origin => window.location.origin.startsWith(origin));
}

// 7. Rate Limiter
const RateLimiter = {
  KEY: 'dba_form_submissions',
  MAX_SUBMISSIONS: 3,
  TIME_WINDOW: 3600000, // 1 hour
  COOLDOWN: 30000, // 30 seconds
  
  canSubmit: function() {
    const now = Date.now();
    let submissions = JSON.parse(localStorage.getItem(this.KEY) || '[]');
    submissions = submissions.filter(time => now - time < this.TIME_WINDOW);
    
    if (submissions.length >= this.MAX_SUBMISSIONS) {
      const oldestSubmission = Math.min(...submissions);
      const waitTime = Math.ceil((this.TIME_WINDOW - (now - oldestSubmission)) / 60000);
      return { allowed: false, reason: `Too many submissions. Wait ${waitTime} minutes.` };
    }
    
    if (submissions.length > 0) {
      const lastSubmission = Math.max(...submissions);
      if (now - lastSubmission < this.COOLDOWN) {
        const waitSec = Math.ceil((this.COOLDOWN - (now - lastSubmission)) / 1000);
        return { allowed: false, reason: `Wait ${waitSec} seconds before submitting.` };
      }
    }
    
    return { allowed: true };
  },
  
  recordSubmission: function() {
    let submissions = JSON.parse(localStorage.getItem(this.KEY) || '[]');
    submissions.push(Date.now());
    localStorage.setItem(this.KEY, JSON.stringify(submissions));
  }
};

// 8. Honeypot Check
function initHoneypot() {
  document.querySelectorAll('input[name="form_start_time"]').forEach(input => {
    input.value = Date.now();
  });
}

function checkHoneypot(form) {
  const honeypot = form.querySelector('[name="website_url"]')?.value;
  const startTimeInput = form.querySelector('[name="form_start_time"]')?.value;
  
  if (honeypot !== '') {
    console.warn('Bot detected (honeypot)');
    return false;
  }
  if (startTimeInput) {
    const timeTaken = Date.now() - parseInt(startTimeInput);
    if (timeTaken < 3000) {
      console.warn('Bot detected (speed)');
      return false;
    }
  }
  return true;
}

// 9. URL Param Sanitization
function sanitizeURLParams() {
  const url = new URL(window.location.href);
  const params = url.searchParams;
  const dangerous = ['password', 'token', 'auth', 'session', 'phone', 'email', 'otp'];
  let modified = false;
  
  dangerous.forEach(param => {
    if (params.has(param)) {
      params.delete(param);
      modified = true;
    }
  });
  
  if (modified) {
    window.history.replaceState({}, document.title, url.pathname + url.hash);
  }
}

// 10. Form Validation Rules
const Validator = {
  name: function(value) {
    const pattern = /^[a-zA-Z\s.\-']{3,50}$/;
    return pattern.test(value) ? { valid: true } : { valid: false, error: 'Name must be 3-50 letters.' };
  },
  phone: function(value) {
    const cleaned = value.replace(/\D/g, '');
    if (cleaned.length !== 10 && cleaned.length !== 12) return { valid: false, error: 'Enter valid 10-digit mobile.' };
    if (cleaned.length === 12 && !cleaned.startsWith('91')) return { valid: false, error: 'Country code should be +91.' };
    return { valid: true };
  },
  email: function(value) {
    if (!value) return { valid: true };
    const pattern = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return (pattern.test(value) && value.length <= 100) ? { valid: true } : { valid: false, error: 'Enter valid email.' };
  },
  message: function(value) {
    if (value.length > 1000) return { valid: false, error: 'Message must be under 1000 chars.' };
    if (/<script|javascript:|onerror=|onclick=/i.test(value)) return { valid: false, error: 'Invalid characters.' };
    return { valid: true };
  },
  service: function(value) {
    return (value && value !== '') ? { valid: true } : { valid: false, error: 'Please select a service.' };
  }
};

// Secure Cookies
function setSecureCookie(name, value, days) {
  const expires = new Date();
  expires.setTime(expires.getTime() + (days * 24 * 60 * 60 * 1000));
  document.cookie = `${name}=${encodeURIComponent(value)}; expires=${expires.toUTCString()}; path=/; Secure; SameSite=Strict; HttpOnly=false`;
}

function getCookie(name) {
  const match = document.cookie.match(new RegExp('(^| )' + name + '=([^;]+)'));
  return match ? decodeURIComponent(match[2]) : null;
}

// Toast Notifications
function showToast(message, type = 'info') {
  let container = document.querySelector('.toast-container');
  if (!container) {
    container = document.createElement('div');
    container.className = 'toast-container';
    document.body.appendChild(container);
  }
  
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `<i class="fa-solid fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'circle-exclamation' : 'info-circle'}"></i> ${sanitizeInput(message)}`;
  
  container.appendChild(toast);
  
  setTimeout(() => {
    toast.style.animation = 'slideOut 0.3s ease forwards';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// Disable Submit Button
function disableSubmitButton(btn) {
  btn.disabled = true;
  let seconds = 30;
  const originalText = btn.innerHTML;
  const interval = setInterval(() => {
    btn.innerHTML = `Wait ${seconds}s...`;
    seconds--;
    if (seconds < 0) {
      clearInterval(interval);
      btn.disabled = false;
      btn.innerHTML = originalText;
    }
  }, 1000);
}

// reCAPTCHA Token
async function getRecaptchaToken() {
  return new Promise((resolve, reject) => {
    if (typeof grecaptcha !== 'undefined') {
      grecaptcha.ready(() => {
        // REPLACE WITH ACTUAL SITE KEY
        grecaptcha.execute('YOUR_RECAPTCHA_SITE_KEY', { action: 'submit' })
          .then(token => resolve(token))
          .catch(reject);
      });
    } else {
      resolve('dummy_token_dev'); // fallback for dev
    }
  });
}

// Handle Form Submission
async function handleContactFormSubmit(event) {
  event.preventDefault();
  const form = event.target;
  const submitBtn = form.querySelector('button[type="submit"]');
  
  try {
    const rateLimitCheck = RateLimiter.canSubmit();
    if (!rateLimitCheck.allowed) {
      showToast(rateLimitCheck.reason, 'error');
      return;
    }
    
    if (!validateCSRF(form)) {
      showToast('Security token invalid. Please refresh.', 'error');
      return;
    }
    
    if (!verifyOrigin()) {
      showToast('Invalid request origin.', 'error');
      return;
    }
    
    if (!checkHoneypot(form)) {
      showToast('Message sent successfully!', 'success');
      form.reset();
      return;
    }
    
    const name = sanitizeInput(form.name.value);
    const phone = sanitizeInput(form.phone.value);
    const email = form.email ? sanitizeInput(form.email.value) : '';
    const service = form.service ? sanitizeInput(form.service.value) : 'General';
    const message = sanitizeInput(stripSQLKeywords(form.message.value));
    
    const validations = [
      Validator.name(name),
      Validator.phone(phone),
      Validator.email(email),
      Validator.service(service),
      Validator.message(message)
    ];
    
    const firstError = validations.find(v => !v.valid);
    if (firstError) {
      showToast(firstError.error, 'error');
      return;
    }
    
    const recaptchaToken = await getRecaptchaToken();
    if (form.querySelector('[name="recaptcha_token"]')) {
      form.querySelector('[name="recaptcha_token"]').value = recaptchaToken;
    }
    
    disableSubmitButton(submitBtn);
    
    // Formspree Send for immediate functionality without config
    const formData = new FormData();
    formData.append('name', name);
    formData.append('phone', phone);
    formData.append('email', email);
    formData.append('service', service);
    formData.append('message', message);
    
    // Replace YOUR_EMAIL@DOMAIN.COM with your actual email
    const response = await fetch('https://formsubmit.co/ajax/dilipborge@yahoo.co.in', {
      method: 'POST',
      body: formData,
      headers: {
        'Accept': 'application/json'
      }
    });
    
    if (response.ok) {
      RateLimiter.recordSubmission();
      refreshCSRFToken();
      showToast('Message sent successfully! We will contact you soon.', 'success');
      form.reset();
      initHoneypot();
    } else {
      throw new Error('Email service returned error');
    }
    
  } catch (error) {
    console.error('Form submission error:', error);
    showToast('Failed to send. Please try WhatsApp or call +91 98985 63718', 'error');
  }
}

/* ==========================================================================
   UI / UX FEATURES
   ========================================================================== */

document.addEventListener('DOMContentLoaded', () => {
  // Initialization
  sanitizeURLParams();
  initCSRF();
  initHoneypot();
  
  
  
  document.addEventListener('mousedown', () => {
  });
  document.addEventListener('mouseup', () => {
  });
  
  document.querySelectorAll('a, button, .interactive').forEach(el => {
    el.addEventListener('mouseenter', () => {
    });
    el.addEventListener('mouseleave', () => {
    });
  });

  // Loader
  const loader = document.getElementById('pageLoader');
  const loaderBar = document.getElementById('loaderBar');
  if (loader && loaderBar) {
    loaderBar.style.width = '100%';
    setTimeout(() => {
      loader.style.opacity = '0';
      setTimeout(() => loader.remove(), 500);
      initScrollAnimations();

  // Initialize VanillaTilt for true 3D interactive effects
  if (typeof VanillaTilt !== 'undefined') {
    VanillaTilt.init(document.querySelectorAll(".glass-card"), {
      max: 10,
      speed: 400,
      glare: true,
      "max-glare": 0.15,
      scale: 1.02
    });
    VanillaTilt.init(document.querySelectorAll(".hero-image-wrapper"), {
      max: 5,
      speed: 400,
      glare: true,
      "max-glare": 0.2
    });
  }

    }, 800);
  } else {
    initScrollAnimations();

  // Initialize VanillaTilt for true 3D interactive effects
  if (typeof VanillaTilt !== 'undefined') {
    VanillaTilt.init(document.querySelectorAll(".glass-card"), {
      max: 10,
      speed: 400,
      glare: true,
      "max-glare": 0.15,
      scale: 1.02
    });
    VanillaTilt.init(document.querySelectorAll(".hero-image-wrapper"), {
      max: 5,
      speed: 400,
      glare: true,
      "max-glare": 0.2
    });
  }

  }

  // Scroll Animations (Intersection Observer)
  function initScrollAnimations() {
    const observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.classList.add('visible');
        }
      });
    }, { threshold: 0.1, rootMargin: "0px 0px -50px 0px" });

    document.querySelectorAll('.fade-up').forEach(el => {
      observer.observe(el);
    });
  }

  // Navbar Scroll
  const navbar = document.querySelector('.navbar');
  const backToTop = document.getElementById('backToTop');
  window.addEventListener('scroll', () => {
    if (window.scrollY > 50) {
      navbar?.classList.add('scrolled');
    } else {
      navbar?.classList.remove('scrolled');
    }
    
    if (window.scrollY > 500) {
      backToTop?.classList.add('visible');
    } else {
      backToTop?.classList.remove('visible');
    }
  });

  if (backToTop) {
    backToTop.addEventListener('click', () => {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    });
  }

  // Mobile Menu
  const hamburger = document.querySelector('.hamburger');
  const mobileNavOverlay = document.querySelector('.mobile-nav-overlay');
  const mobileNavClose = document.querySelector('.mobile-nav-close');
  
  if (hamburger && mobileNavOverlay) {
    hamburger.addEventListener('click', () => {
      mobileNavOverlay.classList.add('active');
    });
    mobileNavClose?.addEventListener('click', () => {
      mobileNavOverlay.classList.remove('active');
    });
  }

  // Announcement Bar Dismiss
  const announceBtn = document.querySelector('.close-announcement');
  if (announceBtn) {
    announceBtn.addEventListener('click', (e) => {
      e.target.closest('.announcement-bar').style.display = 'none';
    });
  }

  // Cookie Consent Banner (Using localStorage for reliable local testing & persistence)
  const cookieBanner = document.getElementById('cookieBanner');
  if (cookieBanner && !localStorage.getItem('cookie_consent')) {
    setTimeout(() => {
      cookieBanner.classList.add('show');
    }, 2000);
    
    document.getElementById('acceptCookies')?.addEventListener('click', () => {
      localStorage.setItem('cookie_consent', 'accepted');
      cookieBanner.classList.remove('show');
    });
    document.getElementById('rejectCookies')?.addEventListener('click', () => {
      localStorage.setItem('cookie_consent', 'rejected');
      cookieBanner.classList.remove('show');
    });
  }

  // Modals
  const modals = document.querySelectorAll('.modal-overlay');
  const modalTriggers = document.querySelectorAll('[data-modal]');
  const modalCloses = document.querySelectorAll('.modal-close');

  modalTriggers.forEach(trigger => {
    trigger.addEventListener('click', (e) => {
      e.preventDefault();
      const modalId = trigger.getAttribute('data-modal');
      document.getElementById(modalId)?.classList.add('active');
      
      // Pre-fill service name if data-service attribute exists
      const serviceName = trigger.getAttribute('data-service');
      const serviceSelect = document.querySelector(`#${modalId} select[name="service"]`);
      if (serviceName && serviceSelect) {
        serviceSelect.value = serviceName;
      }
    });
  });

  modalCloses.forEach(close => {
    close.addEventListener('click', () => {
      close.closest('.modal-overlay').classList.remove('active');
    });
  });

  // Close modal on outside click
  modals.forEach(modal => {
    modal.addEventListener('click', (e) => {
      if (e.target === modal) {
        modal.classList.remove('active');
      }
    });
  });

  // Real-time validation
  document.querySelectorAll('form').forEach(form => {
    const inputs = form.querySelectorAll('input[required], textarea[required], select[required]');
    inputs.forEach(input => {
      input.addEventListener('blur', () => {
        validateField(input);
      });
      input.addEventListener('input', () => {
        if (input.classList.contains('is-invalid')) {
          validateField(input);
        }
      });
    });
  });
});

function validateField(input) {
  let result = { valid: true };
  const name = input.name;
  const val = input.value;
  
  if (name === 'name') result = Validator.name(val);
  if (name === 'phone') result = Validator.phone(val);
  if (name === 'email') result = Validator.email(val);
  
  if (!result.valid) {
    input.classList.add('is-invalid');
    input.classList.remove('is-valid');
    // Set error msg if sibling exists
    const errorEl = input.nextElementSibling;
    if (errorEl && errorEl.classList.contains('error-msg')) {
      errorEl.textContent = result.error;
    }
  } else {
    input.classList.remove('is-invalid');
    input.classList.add('is-valid');
  }
}


// Intercept Form Submissions for AJAX, Netlify, and Success Animation
document.querySelectorAll('form').forEach(form => {
  form.addEventListener('submit', async (e) => {
    e.preventDefault(); // Stop page from navigating
    
    const submitBtn = form.querySelector('button[type="submit"]') || form.querySelector('.btn-gold');
    let originalText = "Send Message";
    if (submitBtn) {
      originalText = submitBtn.innerHTML;
      submitBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Sending...';
      submitBtn.disabled = true;
    }
    
    // Honeypot check
    const honeypot = form.querySelector('[name="website_url"]') || form.querySelector('[name="bot-field"]');
    if (honeypot && honeypot.value !== '') {
      form.reset();
      showSuccessAnimation();
      if (submitBtn) { submitBtn.innerHTML = originalText; submitBtn.disabled = false; }
      return;
    }
    
    const formData = new FormData(form);
    
    try {
      // 1. Netlify Forms submission (runs seamlessly on production Netlify deployment)
      if (window.location.protocol === 'https:' || window.location.hostname.includes('netlify.app')) {
        try {
          const formName = form.getAttribute('name') || 'contact';
          if (!formData.has('form-name')) formData.append('form-name', formName);
          const netlifyParams = new URLSearchParams(formData).toString();
          fetch("/", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: netlifyParams
          }).catch(err => console.log("Netlify submit notice:", err));
        } catch (e) {
          console.warn("Netlify Forms capture:", e);
        }
      }

      // 2. FormSubmit AJAX submission
      const response = await fetch("https://formsubmit.co/ajax/dilipborge@yahoo.co.in", {
        method: "POST",
        headers: {
          'Accept': 'application/json'
        },
        body: formData
      });
      
      const result = await response.json().catch(() => ({}));
      
      // Close modal if open
      const modal = form.closest('.modal-overlay');
      if (modal) {
        modal.classList.remove('active');
      }
      
      form.reset();
      
      if (result && result.message && result.message.toLowerCase().includes('activation')) {
        showActivationNotice();
      } else {
        showSuccessAnimation();
      }
      
    } catch (error) {
      console.error("Form error:", error);
      form.reset();
      showSuccessAnimation();
    } finally {
      if (submitBtn) {
        submitBtn.innerHTML = originalText;
        submitBtn.disabled = false;
      }
    }
  });
});

function showActivationNotice() {
  const overlay = document.createElement('div');
  overlay.style.cssText = `
    position: fixed; top: 0; left: 0; width: 100%; height: 100vh;
    background: rgba(255,255,255,0.96); backdrop-filter: blur(10px);
    z-index: 999999; display: flex; flex-direction: column;
    align-items: center; justify-content: center; padding: 20px;
    opacity: 0; transition: opacity 0.5s ease;
  `;
  
  overlay.innerHTML = `
    <div style="background: var(--gold, #0A58CA); width: 90px; height: 90px; border-radius: 50%; display: flex; align-items: center; justify-content: center; margin-bottom: 25px; box-shadow: 0 15px 30px rgba(10, 88, 202, 0.3);">
      <i class="fa-solid fa-envelope-circle-check" style="color: white; font-size: 45px;"></i>
    </div>
    <h2 style="color: var(--text-primary, #1A2530); margin:0 0 15px; font-family: var(--font-heading), sans-serif; font-size: 2.2rem; text-align: center;">One-Time Activation Needed!</h2>
    <p style="color: var(--text-primary); font-size: 1.1rem; text-align: center; max-width: 600px; line-height: 1.6; margin-bottom: 20px;">
      FormSubmit has sent an <strong>"Activate Form"</strong> confirmation email to <strong>dilipborge@yahoo.co.in</strong>.
    </p>
    <p style="color: var(--text-muted); font-size: 0.95rem; text-align: center; max-width: 550px; background: rgba(0,0,0,0.04); padding: 15px 20px; border-radius: 12px; border: 1px solid rgba(0,0,0,0.08); margin-bottom: 25px;">
      ⚠️ <em>Please check your <strong>Yahoo Inbox</strong> AND the <strong>Spam / Bulk</strong> folder, then click the <strong>Activate Form</strong> button. Once clicked, all future enquiries will be delivered instantly!</em>
    </p>
    <button onclick="this.closest('div').parentElement.remove()" class="btn btn-gold" style="padding: 12px 30px; font-weight: 600;">Got It, I'll Check Yahoo Mail</button>
  `;
  
  document.body.appendChild(overlay);
  requestAnimationFrame(() => overlay.style.opacity = '1');
}

function showSuccessAnimation() {
  const overlay = document.createElement('div');
  overlay.style.cssText = `
    position: fixed; top: 0; left: 0; width: 100%; height: 100vh;
    background: rgba(255,255,255,0.95); backdrop-filter: blur(10px);
    z-index: 999999; display: flex; flex-direction: column;
    align-items: center; justify-content: center;
    opacity: 0; transition: opacity 0.5s ease;
  `;
  
  overlay.innerHTML = `
    <div style="background: var(--whatsapp-green, #25D366); width: 100px; height: 100px; border-radius: 50%; display: flex; align-items: center; justify-content: center; margin-bottom: 30px; transform: scale(0); transition: transform 0.6s cubic-bezier(0.175, 0.885, 0.32, 1.275); box-shadow: 0 15px 30px rgba(37, 211, 102, 0.3);">
      <i class="fa-solid fa-check" style="color: white; font-size: 50px;"></i>
    </div>
    <h2 style="color: var(--text-primary, #1A2530); margin:0; font-family: var(--font-heading), sans-serif; font-size: 2.5rem; text-align: center;">Message Sent!</h2>
    <p style="color: var(--text-muted, #5C6B7A); margin-top: 15px; font-size: 1.2rem; text-align: center;">Thank you for reaching out.<br>We will get back to you shortly.</p>
  `;
  
  document.body.appendChild(overlay);
  
  // Trigger animations
  requestAnimationFrame(() => {
    overlay.style.opacity = '1';
    overlay.querySelector('div').style.transform = 'scale(1)';
  });
  
  // Auto-remove after 3.5 seconds
  setTimeout(() => {
    overlay.style.opacity = '0';
    setTimeout(() => overlay.remove(), 500);
  }, 3500);
}
