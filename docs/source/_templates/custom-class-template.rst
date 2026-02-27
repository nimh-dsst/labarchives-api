# Source - https://stackoverflow.com/a/62613202
# Posted by James Leedham, modified by community. See post 'Timeline' for change history
# Retrieved 2026-02-27, License - CC BY-SA 4.0

{{ fullname | escape | underline}}

.. currentmodule:: {{ module }}

.. autoclass:: {{ objname }}
   :members:                                    
   :show-inheritance:                           
   :inherited-members:                          

   {% block methods %}
   .. automethod:: __init__

   {% if methods %}
   .. rubric:: {{ _('Methods') }}

   .. autosummary::
   {% for item in methods %}
      ~{{ name }}.{{ item }}
   {%- endfor %}
   {% endif %}
   {% endblock %}

   {% block attributes %}
   {% if attributes %}
   .. rubric:: {{ _('Attributes') }}

   .. autosummary::
   {% for item in attributes %}
      ~{{ name }}.{{ item }}
   {%- endfor %}
   {% endif %}
   {% endblock %}
