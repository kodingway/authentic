function table_context_menu(selector, menu) {
  $(document).contextmenu({
      delegate: selector + ' tbody tr',
      menu: menu,
      select: function (event, ui) {
        var ref = $(ui.target).parent('tr').data('ref');
        var action = ui.cmd;
        if (! ref) {
          return;
        }
        $.post('', {
            csrfmiddlewaretoken: window.csrf_token,
            'action': action, 
            'ref': ref 
          },
          function () {
              $.get('', function (html) {
                $(selector + ' tbody').replaceWith($(html).find(selector  + ' tbody'));
                // is is still necessary when only updating tbody ?
                // table_context_menu($('#' + id), menu); 
              });
          }
        );
      }
  });
}

$(function() {
    /* search inputs behaviours */
    $(document).on('click', '.js-confirm', function (e) {
      return confirm(content);
    });
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
    $('#search-input-clear-btn').click(function () {
      $('#search-input').val('').trigger('change');
    });

    /* paginators behaviour */
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
    $('.content').on('click', '.paginator a', function () {
      var href = $(this).attr('href');
      var title = $(this).text();
      update_table(href, function () {
        history.pushState(null, 'page ' + title, href);
      });
      return false;
    });
    $('.messages').delay(3000*(1+$('.messages li').length)).fadeOut('slow');
    $(document).on('gadjo:dialog-loaded', function (e, form) {
      $('.messages', form).delay(3000*(1+$('.messages li', form).length)).fadeOut('slow');
      if ($('.table-container').length) {
        update_table();
      }
    });
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
    $(document).on('click', 'input[type=submit]', function (e) {
      if ($(e.target).data('confirm')) {
        if (! confirm($(e.target).data('confirm'))) {
          return false;
        }
      }
    })
});
