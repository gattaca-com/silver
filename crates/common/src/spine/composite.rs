use std::marker::PhantomData;

use flux::{spine::FluxSpine, tile::{Tile, TileName}};


pub struct CompositeTile<S: FluxSpine, T1: Tile<S>, T2: Tile<S>> {
    tile_1: T1,
    tile_2: T2,
    tile_1_init: bool,
    tile_2_init: bool,
    name: TileName,
    _spine: PhantomData<S>,
}

impl<S: FluxSpine, T1: Tile<S>, T2: Tile<S>> CompositeTile<S, T1, T2> {
    pub fn new(tile_1: T1, tile_2: T2) -> Self {
        let name = tile_1.name().as_str().to_string() + "_" + tile_2.name().as_str();
        Self {
            tile_1, 
            tile_2, 
            tile_1_init: false,
            tile_2_init: false,
            name: TileName::from_str_truncate(name.as_str()),
            _spine: PhantomData::default(),
        }
    }
}

impl<S: FluxSpine, T1: Tile<S>, T2: Tile<S>> Tile<S> for CompositeTile<S, T1, T2> {
    fn loop_body(&mut self, adapter: &mut flux::spine::SpineAdapter<S>) {
        self.tile_1.loop_body(adapter);
        self.tile_2.loop_body(adapter);
    }
    
    fn on_attach(&mut self, adapter: &mut flux::spine::SpineAdapter<S>) {
        self.tile_1.on_attach(adapter);
        self.tile_2.on_attach(adapter);
    }
    
    fn try_init(&mut self, adapter: &mut flux::spine::SpineAdapter<S>) -> bool {
        if !self.tile_1_init {
            self.tile_1_init = self.tile_1.try_init(adapter);
        }
        if !self.tile_2_init {
            self.tile_2_init = self.tile_2.try_init(adapter);
        }
        self.tile_1_init && self.tile_2_init
    }
    
    fn teardown(self, adapter: &mut flux::spine::SpineAdapter<S>) {
        self.tile_1.teardown(adapter);
        self.tile_2.teardown(adapter);
    }
    
    fn name(&self) -> flux::tile::TileName {
        self.name
    }
}