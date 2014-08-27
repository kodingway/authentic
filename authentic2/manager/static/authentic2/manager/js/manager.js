$(function() {
    /* search inputs behaviours */
    $('#search-input').change(function () {
      var params = $.url().param();
      if ($(this).val()) {
        params.search = $(this).val();
      } else {
        if ('search' in params) {
          delete params.search;
        }
      }
      var href = $.url().attr('path')
      if ($.param(params)) {
        href += '?' + $.param(params);
      }
      window.location = href;
    });

    /* role/user table refresh */
    function update_table(href, cb) {
      $.get(href, function (response_text) {
        var $response = $(response_text);
        var $content = $response.find('.table-container');
        if (! $content.length) {
            $content = $response.find('table');
        }
        var $container = $('.table-container');
        if (! $container.length) {
          $container = $('table');
        }
        $container.replaceWith($content);
        if (cb != undefined) {
          cb();
        }
      });
    }
    /* paginator ajax loading */
    $('.content').on('click', '.paginator a', function () {
      var href = $(this).attr('href');
      var title = $(this).text();
      update_table(href, function () {
        history.pushState(null, 'page ' + title, href);
      });
      return false;
    });
    /* dialog load handler */
    $(document).on('gadjo:dialog-loaded', function (e, form) {
      $('.messages', form).delay(3000*(1+$('.messages li', form).length)).fadeOut('slow');
      if ($('.table-container').length) {
        update_table(location.href);
      }
    });
    $(document).on('gadjo:dialog-done', function (e, form) {
      /* on listing pages, do not redirect user elsewhere */
      if ($('.table-container').length) {
        e.preventDefault();
        update_table(location.href);
        $(form).dialog('destroy');
      }
    });
    /* user deletion */
    $(document).on('click', '.js-remove-user', function (e) {
      var $anchor = $(e.target);
      if ($(e.target).data('confirm')) {
        if (! confirm($(e.target).data('confirm'))) {
          return false;
        }
      }
      var $tr = $anchor.parents('tr');
      var ref = $tr.data('ref');
      $.post('', {'csrfmiddlewaretoken': window.csrf_token, 'action': 'remove', 'ref': ref}, function () {
          update_table(window.location.href);
      });
      return false;
    });
    /* confirmation on submit buttons */
    $(document).on('click', 'input[type=submit]', function (e) {
      if ($(e.target).data('confirm')) {
        if (! confirm($(e.target).data('confirm'))) {
          return false;
        }
      }
    })
});
