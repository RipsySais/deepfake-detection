// Menu mobile + zone de dépôt des fichiers (validation côté client).
(function () {
  'use strict';

  var ALLOWED = ['jpg', 'jpeg', 'png', 'webp', 'mp4', 'mov', 'avi', 'webm'];
  var MAX_FILES = 5;
  var MAX_BYTES = 100 * 1024 * 1024;

  // --- Menu mobile -------------------------------------------------------
  var toggle = document.getElementById('menu-toggle');
  var menu = document.getElementById('mobile-menu');
  if (toggle && menu) {
    toggle.addEventListener('click', function () {
      menu.classList.toggle('hidden');
    });
    document.addEventListener('click', function (event) {
      if (!menu.contains(event.target) && !toggle.contains(event.target)) {
        menu.classList.add('hidden');
      }
    });
  }

  // --- Zone de dépôt -----------------------------------------------------
  var zone = document.getElementById('drop-zone');
  var input = document.getElementById('file-input');
  var browse = document.getElementById('browse-button');
  var list = document.getElementById('file-list');
  var error = document.getElementById('file-error');
  var form = document.getElementById('upload-form');
  var submit = document.getElementById('submit-button');
  if (!zone || !input || !form) {
    return;
  }

  function extension(name) {
    var parts = name.toLowerCase().split('.');
    return parts.length > 1 ? parts.pop() : '';
  }

  function render() {
    list.innerHTML = '';
    Array.prototype.forEach.call(input.files, function (file) {
      var item = document.createElement('li');
      item.textContent = file.name + ' (' +
        (file.size / (1024 * 1024)).toFixed(1) + ' Mo)';
      list.appendChild(item);
    });
  }

  function validate() {
    var files = Array.prototype.slice.call(input.files);
    var problem = '';
    if (files.length > MAX_FILES) {
      problem = 'Maximum ' + MAX_FILES + ' fichiers par analyse.';
    }
    files.forEach(function (file) {
      if (ALLOWED.indexOf(extension(file.name)) === -1) {
        problem = file.name + ' : format non pris en charge.';
      } else if (file.size > MAX_BYTES) {
        problem = file.name + ' dépasse 100 Mo.';
      }
    });
    error.textContent = problem;
    return problem === '';
  }

  browse.addEventListener('click', function () {
    input.click();
  });
  input.addEventListener('change', function () {
    render();
    validate();
  });

  ['dragenter', 'dragover'].forEach(function (name) {
    zone.addEventListener(name, function (event) {
      event.preventDefault();
      zone.classList.add('border-blue-600');
    });
  });
  ['dragleave', 'drop'].forEach(function (name) {
    zone.addEventListener(name, function (event) {
      event.preventDefault();
      zone.classList.remove('border-blue-600');
    });
  });
  zone.addEventListener('drop', function (event) {
    input.files = event.dataTransfer.files;
    render();
    validate();
  });

  form.addEventListener('submit', function (event) {
    if (input.files.length === 0) {
      event.preventDefault();
      error.textContent = 'Choisissez au moins un fichier.';
      return;
    }
    if (!validate()) {
      event.preventDefault();
      return;
    }
    submit.disabled = true;
    submit.textContent = 'Analyse en cours…';
  });
}());
