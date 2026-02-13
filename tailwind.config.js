module.exports = {
  content: ["./sogs/templates/**/*.{html,js}"],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        accent: '#00e97b',
        lightGray: '#585858',
        darkGray: '#272726'
      }
    },
    screens : {
      'xs'    : '365px',
      'sm'    : '640px',
      'md'    : '768px',
      'lg'    : '1024px',
      'xl'    : '1280px',
      '2xl'   : '1536px'
    }
  }

}
