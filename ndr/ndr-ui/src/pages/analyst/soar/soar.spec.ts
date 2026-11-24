import { ComponentFixture, TestBed } from '@angular/core/testing';

import { Soar } from './soar';

describe('Soar', () => {
  let component: Soar;
  let fixture: ComponentFixture<Soar>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [Soar]
    })
    .compileComponents();

    fixture = TestBed.createComponent(Soar);
    component = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
