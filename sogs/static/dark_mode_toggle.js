var htmlElement = document.getElementById("html");
var moonIcon = document.getElementById("moonIcon");
var sunIcon = document.getElementById("sunIcon");

function setPageTheme(){
  if (localStorage.theme === 'dark' || (!('theme' in localStorage) && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
    htmlElement.classList.add('dark')
    sunIcon.style.display = 'block'
    moonIcon.style.display = 'none'
  } else {
    htmlElement.classList.remove('dark')
    sunIcon.style.display = 'none'
    moonIcon.style.display = 'block'
  }
}

function toggleDarkMode(){
  if (!'theme' in localStorage || localStorage.theme === 'light') {
    localStorage.theme = 'dark'
    setPageTheme();
  } else {
    localStorage.theme = 'light'
    setPageTheme();
  }
}

modal = document.getElementById('modal');
function handleOpenModalClick() {
  modal.style.display = 'block';
}

function handleCloseModalClick() {
  modal.style.display = 'none';
}

setPageTheme();
