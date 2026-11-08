// Local, synthetic fixtures shaped like the two governed query contracts.
export const subjects = { builder: 'alice@fixture.test', viewer: 'bob@fixture.test' };
export const rows = {
  'readiness-notes': [
    { program_id: 'program-a', assembly_id: 'DEMO-A101', system_name: 'Structures', readiness_pct: 84 },
    { program_id: 'program-a', assembly_id: 'DEMO-A102', system_name: 'Avionics', readiness_pct: 91 },
    { program_id: 'program-b', assembly_id: 'DEMO-B201', system_name: 'Thermal', readiness_pct: 72 },
  ],
  'supplier-evidence': [
    {
      program_id: 'program-a',
      po_line_id: 'DEMO-PO101',
      supplier_alias: 'Supplier Alpha',
      days_late: 3,
    },
    {
      program_id: 'program-a',
      po_line_id: 'DEMO-PO102',
      supplier_alias: 'Supplier Delta',
      days_late: 1,
    },
    { program_id: 'program-b', po_line_id: 'DEMO-PO201', supplier_alias: 'Supplier Beta', days_late: 0 },
  ],
};
