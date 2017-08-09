(function () {
  var spans = document.getElementsByClassName('js-seconds-until');
  if (! spans.length) {
    return;
  }
  var span = spans[0];
  var timeout_id;
  var initial_time = Date.now();
  var until = initial_time + parseInt(span.textContent) * 1000;

  function decrease_seconds() {
    var now = Date.now();
    var duration = (until - now) / 1000;
    if (duration < 1) {
       /* remove the container */
       span.parentNode.parentNoderemoveChild(span.parentNode);
    } else {
       /* decrease seconds before retry */
       span.textContent = Math.floor(duration).toString();
    }
  }
  timeout_id = setInterval(decrease_seconds, 500);
})()
