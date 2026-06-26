function sfaeReplaceDocument(html) {
  var doc = new DOMParser().parseFromString(html, 'text/html');
  document.title = doc.title || '';
  document.body.innerHTML = doc.body.innerHTML;
  var s = doc.querySelector('style');
  if (s) {
    var os = document.querySelector('style');
    if (os) os.textContent = s.textContent;
  }
}

function sfaeMissingInputs(container) {
  var missing = [];
  if (!container) return missing;
  container.querySelectorAll('input:not(:disabled)').forEach(function(input) {
    if (input.dataset.required === 'true' && !input.value.trim()) {
      missing.push(input);
    }
  });
  return missing;
}

function sfaeFlashMissing(inputs) {
  inputs.forEach(function(input) {
    input.classList.remove('is-missing');
    void input.offsetWidth;
    input.classList.add('is-missing');
  });
}

function sfaeUpdateSubmitState(container) {
  if (!container) return;
  var submit = container.querySelector('[data-submit]');
  if (!submit) return;
  var incomplete = sfaeMissingInputs(container).length > 0;
  submit.dataset.incomplete = incomplete ? 'true' : 'false';
  submit.setAttribute('aria-disabled', incomplete ? 'true' : 'false');
}

function sfaeWireSubmitState(container) {
  if (!container) return;
  container.addEventListener('input', function(event) {
    if (event.target && event.target.classList) {
      event.target.classList.remove('is-missing');
    }
    sfaeUpdateSubmitState(container);
  });
  container.addEventListener('change', function(event) {
    if (event.target && event.target.classList) {
      event.target.classList.remove('is-missing');
    }
    sfaeUpdateSubmitState(container);
  });
  sfaeUpdateSubmitState(container);
}
