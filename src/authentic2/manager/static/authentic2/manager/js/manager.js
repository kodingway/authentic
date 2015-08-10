(function($, window, undefined) {
    $.fn.values = function(data) {
        var els = this.find(':input').get();

        if(arguments.length === 0) {
            // return all data
            data = {};

            $.each(els, function() {
                if (this.name && !this.disabled && (this.checked
                                || /select|textarea/i.test(this.nodeName)
                                || /text|hidden|password/i.test(this.type))) {
                    if(data[this.name] == undefined){
                        data[this.name] = [];
                    }
                    data[this.name].push($(this).val());
                }
            });
            return data;
        } else {
            $.each(els, function() {
                if (this.name && data[this.name]) {
                    var names = data[this.name];
                    var $this = $(this);
                    if(Object.prototype.toString.call(names) !== '[object Array]'){
                        names = [names]; //backwards compat to old version of this code
                    }
                    if(this.type == 'checkbox' || this.type == 'radio') {
                        var val = $this.val();
                        var found = false;
                        for(var i = 0; i < names.length; i++){
                            if(names[i] == val){
                                found = true;
                                break;
                            }
                        }
                        $this.attr("checked", found);
                    } else {
                        $this.val(names[0]);
                    }
                }
            });
            return this;
        }
    };
    $(function() {
        /* Copied from http://stackoverflow.com/questions/1489486/jquery-plugin-to-serialize-a-form-and-also-restore-populate-the-form/1490431#1490431
         * by mkoryak
         * jQuery.values: get or set all of the name/value pairs from child input controls
         * @argument data {array} If included, will populate all child controls.
         * @returns element if data was provided, or array of values if not
        */

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

        /* content column update */
        function update_content(href, state, push) {
          /* make the back button work */
          if (push) {
              window.history.pushState(state, window.document.tile, href);
          }
          url = window.location.href;
          $.get(url, function (response_text) {
            var $response = $(response_text);
            var $content = $response.find('#content .content');
            var $container = $('#content .content');
            $container.replaceWith($content);
            $(window.document).trigger('manager:update-content');
          });
        }
        window.update_content = update_content;

        /* document popstate  */
        $(window).on('popstate', function (e) {
            var state = e.originalEvent.state;
            if (state != undefined) {
                if ('form' in state) {
                   $(state.form).values(state.values);
                }
            }
            update_content(window.document.location);
            return true;
        });

        /* paginator ajax loading */
        $(document).on('click', '.paginator a', function () {
          var href = $(this).attr('href');
          var title = $(this).text();
          update_content(href, undefined, true);
          return false;
        });
        /* dialog load handler */
        $(document).on('gadjo:dialog-loaded', function (e, form) {
          $('.messages', form).delay(3000*(1+$('.messages li', form).length)).fadeOut('slow');
          if ($('.table-container').length) {
            update_content(location.href);
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
              update_content(window.location.href);
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
        $(document).on('change', '#id_generate_password', function (e) {
            if ($(e.target).is(':checked')) {
                $('#id_send_mail').prop('disabled', true);
                $('#id_send_mail').data('old_value', $('#id_send_mail').is(':checked'));
                $('#id_send_mail').prop('checked', true);
                $('#id_password1').prop('disabled', true);
                $('#id_password2').prop('disabled', true);
            } else {
                $('#id_send_mail').prop('disabled', false);
                $('#id_send_mail').prop('checked', $('#id_send_mail').data('old_value'));
                $('#id_password1').prop('disabled', false);
                $('#id_password2').prop('disabled', false);
            }
        });
        $(document).on('click.manager', 'table tr[data-url][rel=popup], button[rel=popup]', displayPopup);
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
        var timer;
        $('#search-form').on('input propertychange change', 'input,select', function (e) {
          var $form = $('#search-form');
          window.clearTimeout(timer);
          timer = window.setTimeout(function () {
            var query = $form.serialize();
            if (window.location.href.split('?')[1] == query) {
                return;
            };
            update_content('?' + query, {'form': '#search-form', 'values': $form.values()}, true);
          }, 600);

        });
        if ($('#search-form').length) {
            window.history.replaceState({'form': '#search-form', 'values': $('#search-form').values()}, window.document.title, window.location.href)
        }
        $(window.document).trigger('manager:update-content');
    });
})(jQuery, window)
