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
    /* user deletion */
    $(document).on('click', '.js-remove-object', function (e) {
      var $anchor = $(e.target);
      if ($(e.target).data('confirm')) {
        if (! confirm($(e.target).data('confirm'))) {
          return false;
        }
      }
      var $tr = $anchor.parents('tr');
      var pk = $tr.data('pk');
      var pk_arg = $anchor.data('pk-arg');
      var post_content = {
         'csrfmiddlewaretoken': window.csrf_token,
        'action': 'remove'}
      post_content[pk_arg] = pk
      $.post('', post_content, function () {
          update_table(window.location.href);
      });
      return false;
    });
    /* confirmation on submit buttons */
    $(document).on('click', 'input[type=submit]', function (e) {
      if ($(e.target).data('confirm')) {
        if (! confirm($(e.target).data('confirm'))) {
          e.preventDefault();
          return false;
        }
      } else if ($(e.target).data('url')) {
       e.preventDefault();
       return displayPopup.apply($(e.target), [e]);
      }
    })
    $(document).on('change', '#id_generate_new_password', function (e) {
        if ($(e.target).is(':checked')) {
            $('#id_send_mail').prop('disabled', true);
            $('#id_password1').prop('disabled', true);
            $('#id_password2').prop('disabled', true);
        } else {
            $('#id_send_mail').prop('disabled', false);
            $('#id_password1').prop('disabled', false);
            $('#id_password2').prop('disabled', false);
        }
    });
    $(document).on('click.manager', 'table tr[data-url][rel=popup]', displayPopup);
    $(document).on('click.manager', 'table tr[data-url]:not([rel=popup])', function (e) {
            window.location.href = $(this).data('url');
    });
    /* Prepopulate slug fields */
    $('#id_slug').data('_changed', false);
    $(document).on('change', '#id_slug', function (e) {
        $(e.target).data('_changed', true);
    });
    $(document).on('gadjo:dialog-loaded', function (e, form) {
        if ($('#id_slug').val()) {
            $('#id_slug').data('_changed', true);
        }
    });
    $(document).on('keyup', '#id_name', function (e) {
        var $this = $(this);
        var $target = $(e.target);
        var $slug = $('#id_slug');
        if (! $slug.data('_changed')) {
            $slug.val(URLify($target.val()));
        }
    });
});
