function wp_action(data, svg_area, silent) {
  var silent = silent || false;
  if (!silent) {
    total_packets += 1;
  }
  if (total_packets == 1) {
    $('#edit_counter').html('You have listened to <span>' + total_packets + ' edit</span>.');
  } else {
    $('#edit_counter').html('You have listened to a total of <span>' + insert_comma(total_packets) + ' packets</span>.');
  }
  var now = new Date();
  edit_times.push(now);
  compute_and_update_epm(svg_area);
  var opacity = 1 / (100 / edit_times.length);
  if (opacity > 0.5) {
    opacity = 0.5;
  }
  /*rate_bg.attr('opacity', opacity)*/

  var size = data.packet_length;
  var label_text = data.page_title;
  var csize = size;
  var no_label = false;
  var type = data.type;

  var circle_id = 'd' + ((Math.random() * 100000) | 0);
  var abs_size = Math.abs(size);
  size = Math.max(Math.sqrt(abs_size) * scale_factor, 3);

  Math.seedrandom(data.page_title)
  var x = Math.random() * (width - size) + size;
  var y = Math.random() * (height - size) + size;
  if (!silent) {
    play_sound(size, type, 1)
  }

  if (silent) {
    var starting_opacity = 0.2;
  } else {
    var starting_opacity = 1;
  }

  var circle_group = svg_area.append('g')
    .attr('transform', 'translate(' + x + ', ' + y + ')')
    .attr('fill', edit_color)
    .style('opacity', starting_opacity)

  var ring = circle_group.append('circle')
    .attr({
      r: size + 20,
      stroke: 'none'
    })
    .transition()
    .attr('r', size + 40)
    .style('opacity', 0)
    .ease(Math.sqrt)
    .duration(2500)
    .remove();

  var circle_container = circle_group.append('a')
    .attr('xlink:href', data.url)
    .attr('target', '_blank')
    .attr('fill', svg_text_color);

  var circle = circle_container.append('circle')
    .classed(type, true)
    .attr('r', size)
    .transition()
    .duration(max_life)
    .style('opacity', 0)
    .each('end', function () {
      circle_group.remove();
    })
    .remove();

  circle_container.on('mouseover', function () {
    if (no_label) {
      no_label = false;
      circle_container.append('text')
        .text(label_text)
        .classed('article-label', true)
        .attr('text-anchor', 'middle')
        .transition()
        .delay(1000)
        .style('opacity', 0)
        .duration(2000)
        .each('end', function () { no_label = true; })
        .remove();
    }

  });

  if (s_titles && !silent) {
    var text = circle_container.append('text')
      .text(label_text)
      .classed('article-label', true)
      .attr('text-anchor', 'middle')
      .transition()
      .delay(1000)
      .style('opacity', 0)
      .duration(2000)
      .each('end', function () { no_label = true; })
      .remove();
  } else {
    no_label = true;
  }
}

function initConnection(svg_area) {
  const evtSource = new EventSource("http://localhost:9999/events?stream=messages")

  evtSource.onmessage = function (resp) {
    const lid = "en"
    var data = JSON.parse(resp.data);

    if (!all_loaded) {
      return;
    }

    console.log(data)

    if (data.type === "CNAME") {
      if (user_announcements) {
        newuser_action(data, lid, svg_area);
      }
      var nu_str = '<a href="http://' + lid + '.wikipedia.org/w/index.php?title=User_talk:' + data.user + '&action=edit&section=new">' + data.user + '</a>';
      nu_str += ' joined ' + lid + ' Wikipedia! Welcome!';
      log_rc(nu_str, 20);
    } else {
      if (!isNaN(data.packet_length)) {
        var rc_str = `<a href="http://${data.source_ip}" target="_blank">${data.source_ip}</a> sent ${Math.abs(data.packet_length)} bytes to <a href="http://${data.destination_ip}" target="_blank">${data.destination_ip}</a>`

        // rc_str += ' <a href="' + data.url + '" target="_blank">' + data.page_title + '</a> ';
        // if (data.is_anon) {
        //     rc_str += ' <span class="log-anon">(unregistered user)</span>';
        // }
        rc_str += ` <span class="log-${data.type}">(${data.type})</span>`;
        // if (data.revert) {
        //     rc_str += ' <span class="log-undo">(undo)</span>';
        // }
        // rc_str += ' <span class="lang">(' + lid + ')</span>';
        log_rc(rc_str, 20);

        wp_action(data, svg_area);
      } else if (!isNaN(data.packet_length)) {
        wp_action(data, svg_area, true);
      }
    }
  };
}

var log_rc = function (rc_str, limit) {
  $('#rc-log').prepend('<li>' + rc_str + '</li>');
  if (limit) {
    if ($('#rc-log li').length > limit) {
      $('#rc-log li').slice(limit, limit + 1).remove();
    }
  }
};
/*
var rate_bg = svg.append('rect')
    .attr('opacity', 0.0)
    .attr('fill', 'rgb(41, 128, 185)')
    .attr('width', width)
    .attr('height', height)
*/
function play_sound(size, type, volume) {
  var max_pitch = 100.0;
  var log_used = 1.0715307808111486871978099;
  var pitch = 100 - Math.min(max_pitch, Math.log(size + log_used) / Math.log(log_used));
  var index = Math.floor(pitch / 100.0 * Object.keys(celesta).length);
  var fuzz = Math.floor(Math.random() * 4) - 2;
  index += fuzz;
  index = Math.min(Object.keys(celesta).length - 1, index);
  index = Math.max(1, index);
  if (current_notes < note_overlap) {
    current_notes++;
    if (type == 'CNAME') {
      celesta[index].play();
    } else {
      clav[index].play();
    }
    setTimeout(function () {
      current_notes--;
    }, note_timeout);
  }
}

function play_random_swell() {
  var index = Math.round(Math.random() * (swells.length - 1));
  swells[index].play();
}

function newuser_action(data, lid, svg_area) {
  play_random_swell();
  var messages = ['Welcome to ' + data.user + ', Wikipedia\'s newest user!',
  'Wikipedia has a new user, ' + data.user + '! Welcome!',
  'Welcome, ' + data.user + ' has joined Wikipedia!'];
  var message = Math.round(Math.random() * (messages.length - 1));
  var user_link = 'http://' + lid + '.wikipedia.org/w/index.php?title=User_talk:' + data.user + '&action=edit&section=new';
  var user_group = svg_area.append('g');

  var user_container = user_group.append('a')
    .attr('xlink:href', user_link)
    .attr('target', '_blank');

  user_group.transition()
    .delay(7000)
    .remove();

  user_container.transition()
    .delay(4000)
    .style('opacity', 0)
    .duration(3000);

  user_container.append('rect')
    .attr('opacity', 0)
    .transition()
    .delay(100)
    .duration(3000)
    .attr('opacity', 1)
    .attr('fill', newuser_box_color)
    .attr('width', width)
    .attr('height', 35);

  var y = width / 2;

  user_container.append('text')
    .classed('newuser-label', true)
    .attr('transform', 'translate(' + y + ', 25)')
    .transition()
    .delay(1500)
    .duration(1000)
    .text(messages[message])
    .attr('text-anchor', 'middle');

}

var return_hash_settings = function () {
  var hash_settings = window.location.hash.slice(1).split(',');
  for (var i = 0; i < hash_settings.length + 1; i++) {
    if (hash_settings[i] === '') {
      hash_settings.splice(i, 1);
    }
  }
  return hash_settings;
};

var return_lang_settings = function () {
  var enabled_hash = return_hash_settings();
  enabled_langs = [];
  for (var i = 0; i < enabled_hash.length + 1; i++) {
    var setting = enabled_hash[i];
    if (langs[setting]) {
      enabled_langs.push(setting);
    }
  }
  return enabled_langs;
};

var set_hash_settings = function (langs) {
  if (langs[0] === '') {
    langs.splice(0, 1);
  }
  window.location.hash = '#' + langs.join(',');
};

var enable = function (setting) {
  var hash_settings = return_hash_settings();
  if (setting && hash_settings.indexOf(setting) < 0) {
    hash_settings.push(setting);
  }
  set_hash_settings(hash_settings);
};

var disable = function (setting) {
  var hash_settings = return_hash_settings();
  var setting_i = hash_settings.indexOf(setting);
  if (setting_i >= 0) {
    hash_settings.splice(setting_i, 1);
  }
  set_hash_settings(hash_settings);
};

window.onhashchange = function () {
  var hash_settings = return_hash_settings();
  for (var lang in SOCKETS) {
    if (hash_settings.indexOf(lang) >= 0) {
      if (!SOCKETS[lang].connection || SOCKETS[lang].connection.readyState == 3) {
        SOCKETS[lang].connect();
        $('#' + lang + '-enable').prop('checked', true);
      }
    } else {
      if ($('#' + lang + '-enable').is(':checked')) {
        $('#' + lang + '-enable').prop('checked', false);
      }
      if (SOCKETS[lang].connection) {
        SOCKETS[lang].close();
      }
    }
  }
  if (hash_settings.indexOf('notitles') >= 0) {
    s_titles = false;
  } else {
    s_titles = true;
  }
  if (hash_settings.indexOf('nowelcomes') >= 0) {
    s_welcome = false;
  } else {
    s_welcome = true;
  }
  set_hash_settings(hash_settings);
};

var make_click_handler = function ($box, setting) {
  return function () {
    if ($box.is(':checked')) {
      enable(setting);
    } else {
      disable(setting);
    }
  };
};

var epm_text = false;
var epm_container = {};
var epm_lastupdate = false;

function maybe_compute_epm(svg_area) {
  var now = new Date();
  if (!epm_lastupdate || now.getTime() - epm_lastupdate.getTime() >= 5000) {
    compute_and_update_epm(svg_area);
    epm_lastupdate = now;
  }
}

function compute_and_update_epm(svg_area) {
  var now = new Date();
  edit_times = edit_times.filter(t => (now.getTime() - t.getTime()) < 60000);
  // Find the edit rate for the past minute over each WINDOW_INTERVAL ms,
  // then compute a weighted moving average of those windows.
  // TODO exponential smoothing instead of linear?
  var windows = [];
  var smoothed = 0;
  var denom = 0;
  const WINDOW_INTERVAL = 10000;
  const N = 60000 / WINDOW_INTERVAL;
  var deltas = edit_times.map(t => now.getTime() - t.getTime());
  for (var i = 0; i < N; i++) {
    windows[i] = deltas.filter(d =>
      (d < (i + 1) * WINDOW_INTERVAL)
      && (d > i * WINDOW_INTERVAL)
    ).length;
    smoothed += windows[i] * (N - i) * N;
    denom += (N - i);
  }
  smoothed /= denom;
  update_epm(Math.round(smoothed), svg_area);
}

function update_epm(epm, svg_area) {
  if (!epm_text) {
    epm_container = svg_area.append('g')
      .attr('transform', 'translate(0, ' + (height - 25) + ')');

    var epm_box = epm_container.append('rect')
      .attr('fill', newuser_box_color)
      .attr('opacity', 0.5)
      .attr('width', 135)
      .attr('height', 25);

    epm_text = epm_container.append('text')
      .classed('newuser-label', true)
      .attr('transform', 'translate(5, 18)')
      .style('font-size', '.8em')
      .text(epm + ' edits per minute');

  } else if (epm_text.text) {
    epm_text.text(epm + ' edits per minute');
  }
}

var tag_area = {},
  tag_text = false,
  tag_box = false;

function update_tag_warning(svg_area) {
  if (TAG_FILTERS.length == 0) {
    if (!$.isEmptyObject(tag_area)) {
      tag_area.remove();
      tag_area = {}, tag_text = false;
    }
    return
  }
  if (!tag_text) {
    tag_area = svg_area.append('g');
    tag_box = tag_area.append('rect')
      .attr('fill', newuser_box_color)
      .attr('opacity', 0.5)
      .attr('height', 25);
    tag_text = tag_area.append('text')
      .classed('newuser-label', true)
      .attr('transform', 'translate(5, 18)')
      .style('font-size', '.8em');
  }
  tag_area.attr('transform', 'translate(0, ' + (height - 50) + ')');
  tag_text.text('Listening to: #' + TAG_FILTERS.join(', #'));
  var tag_bbox = tag_text.node().getBBox();
  tag_box.attr('width', tag_bbox.width + 10);
  s_welcome = false;
}

var insert_comma = function (s) {
  s = s.toFixed(0);
  if (s.length > 2) {
    var l = s.length;
    var res = "" + s[0];
    for (var i = 1; i < l - 1; i++) {
      if ((l - i) % 3 == 0)
        res += ",";
      res += s[i];
    }
    res += s[l - 1];

    res = res.replace(',.', '.');

    return res;
  } else {
    return s;
  }
}

function getChromeVersion() {
  // From https://stackoverflow.com/questions/4900436/how-to-detect-the-installed-chrome-version
  // Thanks, Dan.
  var raw = navigator.userAgent.match(/Chrom(e|ium)\/([0-9]+)\./);

  return raw ? parseInt(raw[2], 10) : false;
}
