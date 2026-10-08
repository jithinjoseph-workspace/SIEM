import { ComponentFixture, TestBed } from '@angular/core/testing';

import { NetworkMap } from './network-map';

describe('NetworkMap', () => {
  let component: NetworkMap;
  let fixture: ComponentFixture<NetworkMap>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [NetworkMap]
    })
    .compileComponents();

    fixture = TestBed.createComponent(NetworkMap);
    component = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
