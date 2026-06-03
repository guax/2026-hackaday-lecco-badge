import lvgl

lcd_color_bg      = lvgl.color_hex(0xabc5a0)
lcd_color_fg      = lvgl.color_hex(0x292b29)
lcd_color_fg_dark = lvgl.color_hex(0x080908)

hackaday_grey   = lvgl.color_hex(0x1a1a1a)
hackaday_yellow = lvgl.color_hex(0xe39810) ## adjusted for screen gamma
hackaday_white  = lvgl.color_hex(0xffffff)

base_style = lvgl.style_t()
base_style.init()
base_style.set_text_font(lvgl.font_montserrat_12)
base_style.set_bg_color(lcd_color_bg)
base_style.set_text_color(lcd_color_fg)
base_style.set_radius(0)
base_style.set_border_width(0)
base_style.set_pad_all(0)

content_style = lvgl.style_t()
content_style.init()
content_style.set_text_font(lvgl.font_montserrat_12)
content_style.set_bg_color(lcd_color_bg)
content_style.set_text_color(lcd_color_fg)
content_style.set_radius(0)
content_style.set_border_width(0)
content_style.set_pad_all(0)

menubar_style = lvgl.style_t()
menubar_style.init()
menubar_style.set_text_font(lvgl.font_montserrat_16)
menubar_style.set_bg_color(lcd_color_fg)
menubar_style.set_text_color(lcd_color_bg)
menubar_style.set_radius(0)
menubar_style.set_border_width(0)
menubar_style.set_pad_all(0)

infobar_style = lvgl.style_t()
infobar_style.init()
infobar_style.set_text_font(lvgl.font_montserrat_14)
infobar_style.set_bg_color(lcd_color_bg)
infobar_style.set_text_color(lcd_color_fg_dark)
infobar_style.set_radius(0)
infobar_style.set_border_width(0)
infobar_style.set_pad_all(0)

lvg_color_black  	= lvgl.color_hex(0x000000)
lvg_color_red   	= lvgl.color_hex(0x990000)
lvg_color_green 	= lvgl.color_hex(0x006600)

# Packet analyser type colors
pkt_color_advert  = lvgl.color_hex(0xff9800)  # Orange
pkt_color_grp     = lvgl.color_hex(0x4caf50)  # Green
pkt_color_txt     = lvgl.color_hex(0x9c27b0)  # Purple
pkt_color_ack     = lvgl.color_hex(0x2196f3)  # Blue
pkt_color_path    = lvgl.color_hex(0x00bcd4)  # Cyan
pkt_color_unknown = lvgl.color_hex(0xf44336)  # Red
pkt_color_rssi    = lvgl.color_hex(0x888888)  # Grey
pkt_color_route_fld = lvgl.color_hex(0xf44336)  # Red
pkt_color_route_dir = lvgl.color_hex(0x4caf50)  # Green
