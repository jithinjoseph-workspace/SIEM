import { ComponentFixture, TestBed } from '@angular/core/testing';

import { AiActivity } from './ai-activity';

describe('AiActivity', () => {
  let component: AiActivity;
  let fixture: ComponentFixture<AiActivity>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [AiActivity]
    })
    .compileComponents();

    fixture = TestBed.createComponent(AiActivity);
    component = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
