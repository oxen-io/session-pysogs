function toggleDarkMode() {
    var element = document.getElementById("html");
    if (element.classList.contains('dark') ) {
        element.classList.remove('dark')
    } else {
        element.classList.add('dark');
    }
}