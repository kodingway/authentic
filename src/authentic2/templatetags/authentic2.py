from django import template

register = template.Library()


@register.tag('addtoblock')
def addtoblock(parser, token):
    try:
        tag_name, block_name = token.split_contents()
    except ValueError:
        raise template.TemplateSyntaxError(
            '%r tag requires a single argument' % token.contents.split()[0])
    if not (block_name[0] == block_name[-1] and block_name[0] in ('"', "'")):
        raise template.TemplateSyntaxError(
            '%r tag requireds its argument to be quoted' % tag_name)
    nodelist = parser.parse(('endaddtoblock',))
    parser.delete_first_token()
    return AddToBlock(block_name, nodelist)


class AddToBlock(template.Node):
    def __init__(self, block_name, nodelist):
        self.block_name = block_name[1:-1]
        self.nodelist = nodelist

    def render(self, context):
        output = self.nodelist.render(context)
        dest = context['add_to_blocks'][self.block_name]
        if output not in dest:
            dest.append(output)
        return ''


@register.simple_tag(takes_context=True)
def renderblock(context, block_name):
    output = u'\n'.join(context['add_to_blocks'][block_name])
    return output
