const byId = (id) => document.getElementById(id);
const view = await fetch('/view.json').then((r) => {
  if (!r.ok) throw Error('App configuration unavailable');
  return r.json();
});
document.title = byId('title').textContent = view.title;
byId('category').textContent = view.category;
byId('plural').textContent = view.plural;
byId('scope').textContent = view.visibility === 'private' ? 'Private to you' : 'Shared with app members';
byId('note-label').textContent = view.entry === 'note' ? 'Readiness note' : 'Supplier follow-up';
for (const program of view.programs) byId('program').add(new Option(program, program));
for (const status of view.statuses) byId('status').add(new Option(status, status));
let selected,
  editing,
  cursor,
  sequence = 0,
  saving = false;
const busy = () => {
  byId('save').disabled = saving;
  byId('program').disabled = saving;
};
function message(text, error = false) {
  byId('feedback').textContent = text;
  byId('feedback').classList.toggle('error', error);
}
async function api(route, body, binary = false) {
  const r = await fetch(route, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!r.ok) {
    let code = '';
    try {
      code = (await r.json()).code ?? '';
    } catch {}
    const e = Error(code || 'request_failed');
    e.status = r.status;
    throw e;
  }
  return binary ? r.blob() : r.json();
}
function problem(e) {
  if (e.status === 412)
    return 'Someone saved a newer version. Your draft is still here. Open the latest entry before saving again.';
  if ([401, 403, 404].includes(e.status))
    return 'Access or the current release changed. Reopen the app from Dreamcatcher.';
  if (e.status === 413) return 'The file exceeds the upload limit.';
  return 'Save or refresh could not finish. Retry with the same input.';
}
const el = (tag, text, cls) => {
  const n = document.createElement(tag);
  n.textContent = text;
  if (cls) n.className = cls;
  return n;
};
function clearEdit() {
  editing = null;
  byId('note').value = '';
  byId('status').value = view.statuses[0];
  byId('file').value = '';
  byId('file-label').hidden = !view.files;
  byId('cancel').hidden = true;
  byId('save').textContent = 'Save ' + view.entry;
}
function rowContext() {
  return { program_id: byId('program').value, row_id: selected };
}
async function entries(append = false) {
  const turn = sequence;
  const data = await api('/api/entries', {
    action: 'list',
    ...rowContext(),
    cursor: append ? cursor : null,
  });
  if (turn !== sequence) return;
  const list = byId('entries');
  if (!append) list.replaceChildren();
  for (const entry of data.items) {
    const item = el('article', '');
    item.append(el('small', entry.status + ' · Version ' + entry.version, 'meta'), el('p', entry.note));
    const edit = el('button', 'Edit', 'secondary');
    edit.onclick = () => {
      if (saving) return;
      editing = entry;
      byId('note').value = entry.note;
      byId('status').value = entry.status;
      byId('file-label').hidden = true;
      byId('cancel').hidden = false;
      byId('save').textContent = 'Save changes';
      byId('note').focus();
    };
    item.append(edit);
    if (entry.has_file) {
      const file = el('button', 'Download evidence', 'secondary');
      file.onclick = async () => {
        try {
          const blob = await api(
            '/api/entries',
            { action: 'download', ...rowContext(), id: entry.id },
            true,
          );
          const url = URL.createObjectURL(blob),
            a = el('a', '');
          a.href = url;
          a.download = 'evidence-' + entry.id + '.bin';
          a.click();
          setTimeout(() => URL.revokeObjectURL(url), 1000);
        } catch (e) {
          message(problem(e), true);
        }
      };
      item.append(file);
    }
    list.append(item);
  }
  cursor = data.next_cursor;
  byId('more').hidden = !cursor;
}
async function choose(id) {
  if (saving) return;
  sequence++;
  selected = id;
  clearEdit();
  byId('entries').replaceChildren();
  byId('more').hidden = true;
  message('');
  byId('editor').hidden = !id;
  byId('selected').textContent = id || 'Select a row';
  for (const btn of byId('rows').children)
    btn.setAttribute('aria-pressed', String(btn.dataset.key === id));
  if (id)
    try {
      await entries();
    } catch (e) {
      message(problem(e), true);
    }
}
async function rows() {
  const turn = ++sequence;
  selected = null;
  byId('entries').replaceChildren();
  byId('rows').replaceChildren();
  byId('editor').hidden = true;
  byId('more').hidden = true;
  byId('selected').textContent = 'Select a row';
  try {
    const data = await api('/api/rows', { program_id: byId('program').value });
    if (turn !== sequence) return;
    for (const row of data.rows) {
      const b = el('button', '', 'row');
      b.dataset.key = row[view.key];
      b.append(
        el('strong', row[view.label]),
        el('small', row[view.key] + ' · ' + row[view.metric] + view.unit),
      );
      b.onclick = () => choose(row[view.key]);
      byId('rows').append(b);
    }
    if (data.rows.length) await choose(data.rows[0][view.key]);
    else message('No visible rows for this program.');
  } catch (e) {
    message(problem(e), true);
  }
}
byId('program').onchange = rows;
byId('cancel').onclick = clearEdit;
byId('more').onclick = async () => {
  byId('more').disabled = true;
  try {
    await entries(true);
  } catch (e) {
    message(problem(e), true);
  } finally {
    byId('more').disabled = false;
  }
};
byId('editor').onsubmit = async (event) => {
  event.preventDefault();
  if (!selected || saving) return;
  saving = true;
  busy();
  try {
    const input = {
      action: 'save',
      ...rowContext(),
      note: byId('note').value,
      status: byId('status').value,
    };
    if (editing) {
      input.id = editing.id;
      input.expected_version = editing.version;
    }
    const file = byId('file').files[0];
    if (file && !editing) {
      if (file.size > 32768) {
        message('Choose a file of 32 KiB or less.', true);
        return;
      }
      input.file = {
        name: file.name,
        base64: btoa(String.fromCharCode(...new Uint8Array(await file.arrayBuffer()))),
      };
    }
    // Store only a digest and operation ID. Reload/retry can recover a lost response.
    const digest = await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode(JSON.stringify(input)),
    );
    const slot =
      'save:' + Array.from(new Uint8Array(digest), (x) => x.toString(16).padStart(2, '0')).join('');
    input.operation_id = sessionStorage.getItem(slot) ?? crypto.randomUUID();
    sessionStorage.setItem(slot, input.operation_id);
    let result;
    try {
      result = await api('/api/entries', input);
    } catch (e) {
      if ([400, 412, 413, 422, 507].includes(e.status)) sessionStorage.removeItem(slot);
      throw e;
    }
    sessionStorage.removeItem(slot);
    clearEdit();
    await entries();
    message('Saved version ' + result.version + '.');
  } catch (e) {
    if (e.status === 412) await entries().catch(() => {});
    message(problem(e), true);
  } finally {
    saving = false;
    busy();
  }
};
await rows();
