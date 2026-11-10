import { TestBed } from '@angular/core/testing';

import { Arkime } from './arkime';

describe('Arkime', () => {
  let service: Arkime;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(Arkime);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
