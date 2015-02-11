

if ($('.js-seconds-until').length) {
  var toto = function() {
    var timeout_id;
    var initial_time = Date.now();
    var $spans = $('.js-seconds-until');
    for (var i = 0; i < $spans.length; i++) {
      var $span = $($spans[i]);
      $span.data('until', initial_time + parseInt($span.text())*1000);
    }

    function decrease_seconds() {
      var $spans = $('.js-seconds-until');
      if (! $spans.length) {
        window.clearInterval(timeout_id);
      } else {
        var now = Date.now();
        for (var i = 0; i < $spans.length; i++) {
          var $span = $($spans[i]);
          var until = $span.data('until');
          var duration = (until - now) / 1000;
          if (duration < 1) {
            $span.parent().remove();
          } else {
            $span.text(Math.floor(duration));
          }
        }
      }
    }
    setInterval(decrease_seconds, 500);
  }
  toto();
}
