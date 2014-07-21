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
    $('.content').on('click', '.paginator a', function () {
      var href = $(this).attr('href');
      var title = $(this).text();
      $.get(href, function (response_text) {
        var content = $(response_text).find('.table-container');
        $('.table-container').replaceWith(content);
        history.pushState(null, 'page ' + title, href);
      });
      return false;
    });
    $('.js-table-menu').each(function (i, menu) {
      var $menu = $(menu);
      var selector = $menu.data('selector');
      table_context_menu(selector, $menu);
    })
    $('.messages').delay(3000*(1+$('.messages li').length)).fadeOut('slow');
    $(document).on('gadjo:dialog-loaded', function (e, form) {
      $('.messages', form).delay(3000*(1+$('.messages li', form).length)).fadeOut('slow');
    });
});
