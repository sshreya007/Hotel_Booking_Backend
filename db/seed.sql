-- Demo seed data — 6 hotels with descriptions and one room each, so Browse
-- Hotels has a real-looking catalog to search and book from.
--
-- Safe to re-run: uses fixed UUIDs with ON CONFLICT DO NOTHING, so running
-- this twice against the same database just does nothing the second time.

INSERT INTO hotels (id, name, address, description) VALUES
  ('11111111-1111-1111-1111-111111111111', 'The Ledger Inn', '1 Harbor St, Portsmouth',
   'A restored 19th-century harbourmaster''s office turned boutique hotel, with exposed brick, brass fittings, and views over the working harbour.'),
  ('33333333-3333-3333-3333-333333333333', 'Bay View Suites', '22 Coastal Rd, Brighton',
   'Modern suites steps from the seafront, each with a private balcony facing the water. Popular for weekend breaks and quiet off-season stays.'),
  ('77777777-7777-7777-7777-777777777777', 'Highland Lodge', '4 Glen Path, Aviemore',
   'A timber lodge at the edge of the forest, built around a stone fireplace lounge. Close to hiking trails and mountain biking routes.'),
  ('88888888-8888-8888-8888-888888888888', 'City Central Hotel', '150 Market St, Manchester',
   'A no-nonsense business hotel two minutes from the station, with fast check-in, a 24-hour desk, and a small gym on the top floor.'),
  ('99999999-9999-9999-9999-999999999999', 'Riverside Retreat', '9 Millbank, York',
   'A converted mill house on the riverbank, with a walled garden, a small library, and rooms named after the birds that nest along the water.'),
  ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'Garden Boutique Hotel', '31 Orchard Lane, Bath',
   'Eight rooms set around a walled Georgian garden, each individually decorated, with breakfast served on the terrace in warmer months.')
ON CONFLICT (id) DO NOTHING;

INSERT INTO rooms (id, hotel_id, room_number, room_type, price_per_night, max_guests) VALUES
  ('22222222-2222-2222-2222-222222222222', '11111111-1111-1111-1111-111111111111', '101', 'Deluxe Double', 149.00, 2),
  ('44444444-4444-4444-4444-444444444444', '33333333-3333-3333-3333-333333333333', '201', 'Sea View Suite', 219.00, 3),
  ('55555555-5555-5555-5555-555555555555', '77777777-7777-7777-7777-777777777777', '12', 'Forest Cabin Room', 129.00, 4),
  ('66666666-6666-6666-6666-666666666666', '88888888-8888-8888-8888-888888888888', '505', 'Standard Business Room', 99.00, 2),
  ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', '99999999-9999-9999-9999-999999999999', 'Kingfisher', 'Riverview Double', 159.00, 2),
  ('cccccccc-cccc-cccc-cccc-cccccccccccc', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'Rose Room', 'Garden Single', 89.00, 1)
ON CONFLICT (id) DO NOTHING;
